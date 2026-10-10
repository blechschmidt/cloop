# Executor architecture

How a task travels from the orchestrator to a sandbox and back.

The central claim this architecture exists to make good on: **the hub never runs
a harness itself.** It resolves an executor, hands it a `Spec`, and reads back
lines. Everything below is the machinery that keeps that true across four very
different backends, a fleet that can lose nodes mid-task, and a control plane
that must not become the thing it is isolating.

- [The interface](#the-interface)
- [Backends](#backends)
- [Registry and binding](#registry-and-binding)
- [Placement](#placement)
- [Workspace provisioning](#workspace-provisioning)
- [Supervision, health and failover](#supervision-health-and-failover)
- [End to end](#end-to-end)
- [Remote agent enrollment](#remote-agent-enrollment)

---

## The interface

`pkg/executor/executor.go` defines one interface every backend implements:

```go
type Executor interface {
	ID() string                                                          // stable instance id
	Kind() string                                                        // driver name — a Kind* const
	Capabilities() Capabilities                                          // isolation, streaming, limits, platform
	Start(ctx context.Context, spec Spec) (Handle, error)                // launch; workload outlives ctx
	Signal(ctx context.Context, handleID string, sig Signal) error       // interrupt / terminate / kill
	Status(ctx context.Context, handleID string) (Status, error)         // point-in-time snapshot
	Stream(ctx context.Context, handleID string) (<-chan LogLine, error) // live output, replayed from start
	HealthCheck(ctx context.Context) error                               // can this node accept work?
}
```

Two properties of this interface are load-bearing and easy to get wrong:

**`ctx` governs the call, not the workload.** Cancelling the context passed to
`Start` aborts the act of starting; it does not kill what started. The Web UI
launches long-lived runs from short-lived HTTP handlers, so tying workload
lifetime to the request context would kill every run the moment its originating
request returned (`executor.go:311-319`). Callers that *do* want ctx-bound
lifetime use the `Run` helper, which wires cancellation to `SignalKill`.

**`Stream` replays.** Output produced between `Start` and `Stream` is buffered
and replayed (bounded, 64 KiB) so a subscriber cannot race the workload's first
writes. The channel never blocks the producer: when a subscriber's buffer fills,
chunks are dropped and the gap is visible as a jump in `LogLine.Seq`
(`internal/logbus`). Silent truncation would be worse than a visible gap.

### Spec, Handle, Status

| Type | Carries | Notes |
| --- | --- | --- |
| `Spec` | `WorkDir`, `Argv`, `Env`, `Labels`, `ResourceLimits`, `TimeoutMinutes` | `Argv` is never shell-quoted — there is no shell. `Env == nil` inherits the control plane's environment on `localprocess`, and means *empty* on `container`. |
| `Spec` (sandbox) | `Image`, `SetupCommands`, `Mounts`, `DisableNetwork`, `SandboxHash` | Derived from the project's [`.cloop/sandbox.yaml`](../reference/sandbox.md). `SandboxHash` records *which* spec produced this workload, so a run can be attributed to the file it was launched under. |
| `Spec` (credentials) | `Secrets`, `Workspace` | Neither holds material. `Secrets` is a `SecretBinding` list — which lease delivered which env names and file paths — so a `revoke` frame can take one credential back mid-run. `Workspace` names a *grant*, never a token. |
| `Handle` | `ID`, `ExecutorID`, `PID`, `StartedAt` | `PID` is 0 where the concept is meaningless (Pods, remote agents). |
| `Status` | `State`, `ExitCode`, `Error` | States: `pending`, `running`, `exited`, `failed`, `killed`, `unknown`. |
| `LogLine` | `HandleID`, `Stream`, `Text`, `Time`, `Seq` | `Seq` gaps mean dropped chunks, not reordering. |

The second and third rows share one property that is easy to lose in a refactor:
**a driver that cannot honour a field refuses the workload rather than dropping
it.** `Spec.SandboxRequirements()` is the single definition of what a given Spec
needs, and both entry points into "start a workload" — `Select` on the failover
path and `CheckSandboxSupport` on the binding path — run it through the same
matcher. A field added there is enforced in both places without anyone
remembering to add a second call.

A `Spec` is persisted by `pkg/executorstore` (so failover can re-dispatch it
verbatim), marshalled across the remote-agent boundary, and echoed into audit
rows. That is why credential material is structurally absent from it rather than
merely omitted by careful call sites: a token placed here would be durable in
three places before anything read it.

### Isolation

`Capabilities().Isolation` is what the host-execution policy reads, so it is a
security-relevant declaration, not a hint:

| Isolation | Meaning | Reported by |
| --- | --- | --- |
| `none` | shares the host's filesystem, network and user | `localprocess` |
| `container` | own filesystem and network namespace, **host kernel** | `container` on the CLI's default runtime (runc/crun) |
| `vm` | a virtual machine or microVM with **a kernel of its own** | `container` configured with a Kata `oci_runtime` |
| `remote` | a different machine entirely | `remote`, `kubernetes` |

### Virtualization is a second axis, not a fifth value

`Capabilities` carries a separate boolean, `Virtualized`, and the reason it is
not simply another `Isolation` value is the last row of that table. A Kata Pod
on a cluster is *both* remote — the machine is not the hub's — and virtualized —
the kernel is not the node's. `Isolation` is one enum field and can carry only
one of those two facts, and it is deliberately **not a total order** (a
container on this host and a process on a remote device are *differently*, not
more or less, isolated), so no single value could mean both without misstating
one of them. `Isolation` therefore keeps the fact a driver always has, and
`Virtualized` carries the one it sometimes adds:

| Driver | `Isolation` | `Virtualized` | `KernelIsolated` | Turned on by |
| --- | --- | --- | --- | --- |
| `localprocess` | `none` | ❌ | ❌ | — |
| `container`, default runtime | `container` | ❌ | ❌ | — |
| `container`, gVisor runtime | `container` | ❌ | ✅ | [`executors.container.oci_runtime`](../guides/enterprise-hosts.md#3-per-project-sandbox-with-gvisor) |
| `container`, Kata runtime | `vm` | ✅ | ✅ | [`executors.container.oci_runtime`](../reference/configuration.md#vm-isolated-sandboxes-kata-containers) |
| `remote` | `remote` | ❌ | ❌ | — |
| `kubernetes`, default class | `remote` | ❌ | ❌ | — |
| `kubernetes`, gVisor RuntimeClass | `remote` | ❌ | ✅ | [`executors.kubernetes.runtime_class`](../guides/enterprise-hosts.md#3-per-project-sandbox-with-gvisor) |
| `kubernetes`, Kata RuntimeClass | `remote` | ✅ | ✅ | [`executors.kubernetes.runtime_class`](../reference/configuration.md#vm-isolated-sandboxes-kata-containers) |

Both drivers decide it from the configured runtime **name**, through one shared
matcher — `executor.IsVirtualizedRuntime` (`pkg/executor/virtualization.go`).
One definition rather than two because the two drivers are naming the same
technology in different vocabularies (an OCI runtime passed to `--runtime`, a
Kubernetes RuntimeClass), and a second copy would be a second chance for the
same sandbox to be described one way by the container driver and another by the
Kubernetes one.

The matcher is deliberately narrow: `kata`, `katacontainers`, any `kata-*` /
`kata.*` name, and the containerd shim spelling `io.containerd.kata.v2`.
Everything else is false. Being wrong here is asymmetric. A **false negative**
under-describes a sandbox — a Kata executor registered under an unrecognised
name is called a container, a project requiring virtualization is refused
placement on something that would have satisfied it, and the operator sees a
refusal they can fix by renaming. A **false positive** tells an operator a
workload runs behind a hypervisor when it shares the host kernel, and *places*
work that was required to be virtualized onto something that is not. So gVisor's
`runsc` reports false even though it is a genuinely stronger boundary than runc:
it is a userspace kernel, not a virtual machine, and calling it one would
misstate what an escape reaches.

#### `KernelIsolated` is the third column, and the reason there is one

That last point used to end the discussion, and it left a gap. An operator running
gVisor got a sandbox described as a plain container — indistinguishable from runc —
so a project whose actual requirement was "my task's syscalls must not reach the
host kernel" had no way to ask for one, and `virtualized: true` *actively refused*
the gVisor executor that would have satisfied the intent. A refusal nobody needed
is still an outage.

Hence a second boolean and a second predicate, asking a deliberately different
question:

| Predicate | Question | True for |
| --- | --- | --- |
| `IsVirtualizedRuntime` | is there a hypervisor? | Kata |
| `IsKernelIsolatedRuntime` | are the workload's syscalls served by something other than the executing machine's kernel? | Kata **and** gVisor |

`Capabilities.KernelIsolated` is set from the second, so it is the **union** of
Kata and gVisor and a strict superset of `Virtualized`: virtualization implies
kernel isolation and not the reverse, and the gap between the two columns is
exactly gVisor. `runc` and `crun` are false in both, which is the case the field
exists to exclude — their boundary is namespaces, cgroups and seccomp, so a kernel
bug is a host bug.

It is a separate field rather than a widening of `Virtualized` because the two are
different promises and a project needs to be able to ask for the weaker one. A
`.cloop/sandbox.yaml` saying `capabilities: kernel_isolated: true` is satisfied by
either technology; `virtualized: true` demands a hypervisor and is checked against
the narrower field. Collapsing them in either direction breaks something: widening
`Virtualized` to include gVisor would tell an operator they have a VM when they do
not, and leaving `KernelIsolated` out forces every project with the weaker
requirement to over-ask and watch every `runsc` node in the fleet get rejected for
a property it had provided. The matching constraints are `virtualization` and
`kernel_isolation` — see [Placement](#placement).

Like `Virtualized`, `KernelIsolated` stays false unless the driver is certain,
because `RequireKernelIsolation` is checked against it and a false positive runs a
workload on the host kernel it was told to stay off. Both drivers read it from the
same configured runtime name through the same matcher, so the two claims are
consistent by construction: a name cannot be virtualized without also being
kernel-isolated. Note that `Isolation` stays `container` for gVisor even when
`KernelIsolated` is true, and the two do not conflict — gVisor is a container by
every structural measure that enum describes (namespaces, a cgroup, an image, no
VM). What it changes is *who executes the syscalls*, which is a different axis and
gets a field rather than a fifth enum value nothing else understands.

The name is all either API exposes, which is a real limit — an operator can
register runc under the name `kata` and be believed. That is not a gap a name
matcher can close, and it is why the container driver's [preflight](#container--kind-container-isolation-container-or-vm)
separately proves the host can start a VM at all.

---

## Backends

### `localprocess` — Kind `localprocess`, isolation `none`

Spawns child processes of the hub with `os/exec` at `Spec.WorkDir`. No
isolation: same user, same filesystem, same network. It reports a real OS PID,
which the UI's stop path relies on. It does not create a new process group, so
Ctrl-C at a terminal still reaches children. `TimeoutMinutes` is enforced with a
`time.AfterFunc` that sends SIGKILL.

This is the backend that [strict mode](../security/model.md#the-no-host-execution-guarantee)
exists to forbid. It remains the default for single-user local development,
where the hub and the workload are the same trust domain by definition.

### `container` — Kind `container`, isolation `container` or `vm`

Shells out to the Docker or Podman CLI. The argv is built by a pure function,
`buildRunArgs` (`container/argv.go`), which is why the sandbox flags can be
[exhaustively tested](../security/model.md#the-guarantee--test-table) without a
runtime present. Forced on every invocation:

```
--pull=never  --cap-drop=ALL  --security-opt=no-new-privileges  --read-only
--tmpfs /tmp:rw,nosuid,nodev,exec,size=<N>m
--user <uid derived from the project directory owner>
--network=none              (unless an executor opts in)
--memory-swap == --memory   (swap pinned to the memory ceiling)
--workdir /cloop/work  --volume <project dir>:/cloop/work
```

Only the project directory is mounted. `--pull=never` means a cold image fails
immediately and loudly rather than pulling something unexpected at task time —
pre-pulling is the operator's job. The project directory is also where the
work lands on the host's disk, so it is what a disk limit bounds: no flag can
(`--storage-opt size=` bounds the writable layer, which `--read-only` already
closes), so the driver measures the workspace at the start and on a cost-bounded
interval while the workload runs, refuses a tree already over and stops one that
grows past it (`disklimit.go`, `pkg/executor/internal/diskwatch`). Secrets are forwarded as bare `--env NAME`,
so the runtime reads the value from its own environment and it never appears in
the host process table. A denylist (`deniedExtraArgs` in `argv.go`) rejects operator-supplied
`ExtraArgs` that would undo any of this.

**Two runtime axes.** `executors.container.runtime` picks the *CLI* — podman or
docker. `executors.container.oci_runtime` picks what that CLI hands each
container to, emitted as `--runtime <name>` at the top of the Isolation section
of the argv. Empty means the CLI's own default (runc or crun) and no flag is
emitted at all, so the overwhelmingly common deployment produces a
byte-identical command line to before this field existed.

Naming a Kata runtime (`kata`, `kata-qemu`, `kata-clh`, `kata-runtime`) is what
makes this executor a **VM sandbox**: every container boots inside a lightweight
VM with its own kernel, so a kernel exploit reaches the guest and the host kernel
sits behind a hypervisor. It also changes what the flags *below* the `--runtime`
line are enforced by — under runc they are host-kernel features, under Kata they
are the guest's, applied inside a VM the host kernel never sees into. The
executor then reports `Isolation: vm` and `Virtualized: true`. Setup and
prerequisites: **[the Kata guide](../guides/kata.md)**.

The value is a **name and never a path**. A path here would be a path to a binary
that docker's daemon runs as root, so config that could name an arbitrary
executable would be config that executes arbitrary code as root — the same reason
the CLI itself is allow-listed. A bare name cannot do that: docker resolves it
only against `/etc/docker/daemon.json` and podman only against
`containers.conf`, both root-owned files the operator already controls, so the
name is an indirection through a trusted table rather than a target.
`ValidateOCIRuntime` therefore checks only the *shape* — no path separators, no
leading dash, letters/digits/`.`/`_`/`-`, at most 64 characters — because the set
of legitimate names is open (operators register Kata under whatever name they
like, and clusters do) and a fixed allow-list would reject working deployments.
The narrow judgement is reserved for the VM *claim*, above.

A malformed `oci_runtime` **disables the executor** rather than being cleared to
empty, and it is the only container key that behaves that way. Every other clamp
falls back to a driver default that confines at least as much as the rejected
setting; blanking a Kata runtime falls back to runc, which silently turns the VM
sandbox the operator asked for into a container one while the executor keeps
running and reporting success. A hub that comes up with one fewer executor is a
visible, diagnosable failure; a hub that comes up with a sandbox weaker than its
config describes is not (`clampContainerExecutor`, `pkg/config/executors.go`).

Preflight gains two checks when — and only when — an `oci_runtime` is set, since
a deployment on the CLI's default has nothing here to get wrong and an
always-green finding on every report buries the ones that matter:

| Check | Asks | On failure |
| --- | --- | --- |
| `oci-runtime` | is the name registered with the CLI that has to resolve it? | `fail` on docker, listing the runtimes it *does* have; `warn` on podman, which cannot be asked |
| `kvm` | does `/dev/kvm` exist **and open read-write**? (Kata runtimes only) | `fail`, pointing at nested virtualization or `kvm` group membership |

Only docker can answer the first: `docker info` carries the daemon's Runtimes
table, which is exactly the set `--runtime` resolves against. Podman resolves
against `containers.conf` and exposes only the *active* runtime, with no way to
enumerate the rest — so on podman the finding is a **warning** that the name is
unverified until the first run, never a failure. A probe that cannot distinguish
"absent" from "unenumerable" must not report "absent", because that turns a
working Kata deployment into a startup failure.

The KVM check opens the device rather than stat-ing it. `/dev/kvm` is mode 0660
`root:kvm` on most distributions, so a stat succeeds for a user who cannot use
it, and the failure that actually happens — a rootless podman user outside the
`kvm` group — is invisible to a stat and immediate on an open. Neither check can
prove a VM will boot; the smoke test that follows is what does, and it records
the `oci_runtime` it ran under in its result.

### `remote` — Kind `remote`, isolation `remote`

Runs on an enrolled edge device that dialled *out* to the hub over WebSocket, so
the device needs no inbound port and no static address. See
[Remote agent enrollment](#remote-agent-enrollment).

Handles are durable across disconnects: the hub names the handle, and after a
reconnect the agent resumes output at a byte offset rather than replaying from
zero. One `Executor` therefore spans many WebSocket sessions, and workloads
outlive the connection that started them. Agents heartbeat every 15 s (±25 %
jitter); three missed heartbeats mark the node unreachable (~45 s).

The device shares nothing with the hub, so it either fetches the project's
source tree itself before starting the harness, or — for a project that has no
repository of its own — keeps a working directory of its own that the hub seeds
with the project's state. See
[Workspace provisioning](#workspace-provisioning). Fetching needs `git` on the
device and protocol v3; seeding needs protocol v10. An agent below either is
refused the *placement* rather than trusted to notice.

#### Where the payload runs on the device (Task 20307)

`isolation: remote` is a fact about the network, not about containment. It says
the workload is on another machine whose filesystem the hub cannot read — and it
says exactly that whether the device runs the harness in a container or as a
plain process with the agent's own privileges.

Until Task 20307 it was always the latter. The agent built one
`localprocess.Executor` and used it unconditionally, while its capability
detection reported the `docker`/`podman`/`nerdctl` binaries it had found on
`PATH` and the fleet card rendered them as chips. Nothing was lying on purpose;
there was simply no way for anyone to ask for a container, so "remote" was the
strongest true statement available.

It is now configurable per executor, by an admin, from the Executors panel
(**Sandbox** button) or `PUT /api/executors/{id}/sandbox`:

| Field | Meaning | Empty means |
| --- | --- | --- |
| `mode` | `host` or `container` | unset — the device behaves as it always did |
| `engine` | `docker`, `podman`, `nerdctl` | the device detects one |
| `runtime` | the `--runtime` name: `runc`, `crun`, `runsc`, `kata`… | the engine's default |
| `image` | the sandbox image | the executor's configured default |
| `network` | the container network: `none`, `bridge`, or one the operator created on the device | `none` |

`network` is the one field whose default is both correct and, for most real
projects, insufficient. Deny-by-default is right — a payload that cannot reach
the network cannot exfiltrate what it was given — but everything cloop brokers
is a *network service*: repositories arrive through the git interception proxy,
clusters through the Kubernetes access monitor, the Internet through the egress
broker, each addressed by URL. A container-mode executor left on `none` will be
granted credentials it has no way to spend, and the failure surfaces inside the
sandbox as `Could not resolve host` rather than at the hub as a refusal. Set it
to `bridge`, or to a network you created on the device that reaches the hub.

`host` is refused outright, along with `container:<id>`: both hand the payload
the network namespace the sandbox exists to take away, and with it every service
bound to that device's loopback.

The configuration lives in the control plane (`executor_sandbox`, migrations
0044 and 0047), not on the device, for the reason `project_executors` does: it is an
operator's policy *about* an executor rather than a fact belonging to it. A
device that stored its own containment setting could be asked by its own
operator to misreport it, and the hub would have no way to tell. Instead the hub
reads the row at dispatch and stamps it on every start frame
(`StartPayload.Sandbox`, protocol v8) — so an admin's change in the panel governs
the *next task*, with no agent restart and no window in which the device's idea
of its own containment differs from the control plane's.

Four refusals keep the setting a control rather than a hint. Each exists because
the failure it prevents is silent, useless, or both:

- **A pre-v8 agent is refused container-mode work.** It would not reject an
  unknown `sandbox` field; it would ignore it and run the harness on its host,
  reporting success. `ErrSandboxModeUnsupported`.
- **An unreadable configuration fails the dispatch.** "I could not read whether
  this executor is supposed to be contained" must not resolve to "run it on the
  host" — that is a containment decision made by a busy database, in the weaker
  direction, on a hub too unhealthy to notice. `ErrSandboxModeUnavailable`.
- **A device that cannot provide the configured containment fails the start.** No
  fallback to a host process. See `pkg/executor/agent/driver.go`, which extends
  the container driver's own rule — *an operator who configured a container
  executor and silently got host execution would believe they had an isolation
  boundary they do not have* — one machine further out.

- **A device that cannot start a VM is refused a Kata runtime.** Unlike the three
  above, this failure is loud — and useless with it. The payload arrives, Kata
  launches QEMU with `accel=kvm`, and roughly fifty seconds later the shim gives
  up with `timed out waiting for QMP ready: Connection refused`, naming neither
  KVM nor nested virtualization nor the executor. `ErrVirtualizationUnavailable`.

Only container mode is version-gated. Host and unset are what a pre-v8 agent does
anyway, so refusing those would strand a fleet mid-upgrade for nothing.

Capabilities follow the configuration *and* the device, which is what finally
makes a Kata edge device describable as one without making every other device
falsely describable as one. The runtime the hub names says what an admin asked
for; whether the machine can deliver it is a fact only the machine has, so since
protocol v9 the agent reports it (`AgentCapabilities.Virtualization`, an open of
`/dev/kvm`). `Virtualized` and `KernelIsolated` are reported only when the mode
is `container`, the live session can honour it, *and* — for a Kata runtime — the
device answered yes.

The three conditions fail in different directions on purpose. A runtime recorded
against host mode confines nothing. An executor must not advertise containment
its own `Start` would refuse. And a device with no `/dev/kvm` loses `Virtualized`
outright, because claiming a hypervisor that cannot exist is the false-positive
direction the runtime matcher is written to avoid; it loses `KernelIsolated` too
under Kata, whose isolation *is* the guest kernel, but keeps it under `runsc`,
whose Sentry never opens `/dev/kvm`. A pre-v9 agent is not demoted: absence of
the field is *unknown*, not *no*, and reading a zero value as a denial would
strand every Kata device already deployed.

Credential files follow the payload into the container. The agent writes a
lease's files into a directory it owns under `/dev/shm` and rewrites the
workload's environment onto that path; in container mode it additionally binds
that directory into the sandbox read-only, at the same path. Same path because
the broker baked it into `CLOOP_LEASE_DIR`, `GIT_CONFIG_GLOBAL` and `KUBECONFIG`
before the frame was sent, and the agent's own revocation index points at it —
remapping would break both. Without the bind the workload starts holding paths
that exist one namespace away, which git reports as `could not read Username`.

One operational note, because it is the first thing a container mode meets on a
small device: the driver refuses to run a workload as uid 0. Root inside a
container defeats `--cap-drop=ALL`, so a runtime escape becomes host root. The
sandbox user is derived from the workspace directory's owner, which means an agent
running as root with a root-owned `workdir_root` is refused with a message naming
the fix. The hardened service unit `cloop executor agent install` writes already
runs the agent as a dedicated unprivileged user, so a device onboarded that way
satisfies this without anyone thinking about it.

#### What a device's returned work may hold on the hub (Task 20399)

A device sends a run's work back as a write-back bundle, streamed as result
chunks and closed by a result frame, and a seeded run's project state as one
`project_result` document. The hub holds both in memory until whoever settles
the run collects them. A device is the least trusted party in the system, so
how much it can make the hub hold is bounded at three levels, and every byte is
counted when it is kept and given back when it is dropped:

| Bound | Size | Set by |
| --- | --- | --- |
| One handle's bundle | the cap its spec asked for (`WriteBack.BundleCap`, 32 MiB unless the dispatch named one, at most 128 MiB); none for a push or no write-back | the dispatch, persisted with the handle's row |
| One handle's project state | 640 KiB, and only for a run that was seeded | the protocol |
| One executor, across all its handles | 256 MiB | `executors.remote.max_pinned_writeback_bytes` |
| The hub process, across all executors | 1 GiB | `executors.remote.max_pinned_writeback_total_bytes` |

Before this, each handle took the hard 128 MiB ceiling whatever it had asked
for, chunks were accepted for a handle that had already finished, a collected
bundle could be refilled from offset 0, nothing counted the total, and revoking
the device freed nothing — 128 MiB on each of the 256 finished handles the hub
retains per device, plus the running ones: 32 GiB per device per hub process.

**A handle accepts only what its spec asked for, and nothing late.** The hub
writes what a run may send back into the handle's durable row (`Meta`:
`writeback_mode`, `writeback_cap`, `project_seeded`), so a hub that restarted —
or another member that adopted the run — holds the device to the same cap when
it resends its bundle from offset 0. A row written by an older hub carries none
of this, and its handle gets the hard ceilings rather than a refusal, so a run
in flight across the upgrade still lands. Once a handle has reported its final
status, or its write-back has closed with a result frame, every further chunk or
result is refused before anything is allocated for it. An honest agent sends
chunks, then the result, then the status, and nothing after; a restart from
offset 0 is legal only before the result. None of this is gated on a protocol
version, because it asks nothing of the agent that every agent does not already
do.

**Past a budget, that run's write-back fails** with `ErrWriteBackBudget`, and the
reason — which limit, how much was already held — is recorded on the run, so the
journal says why its work did not come back. What is held for other runs is
untouched. The bundle is kept as one exactly-sized copy per chunk rather than
one growing buffer, and each chunk is counted with 64 bytes
(`ResultChunkOverhead`) for the memory that holds it as well as its own bytes —
so the memory held stays within the allocator's rounding of what is counted,
however a device cuts its bundle up. A device sending one-byte chunks is charged
for one-byte chunks. The copy matters as much as the count: a chunk's bytes
arrive as base64 the JSON decoder reads past newlines in, so a frame padded to
the 1 MiB limit decodes a one-byte chunk over three quarters of a megabyte, and
keeping the decoded slice would keep all of it. A sandbox terminal's inbox, the
one other place the hub queues bytes a device sent, copies for the same reason.

**What is held is let go of** when it is collected; when its run ends without
the result frame that would make it collectable (the run's write-back then says
how much had arrived); when the run is abandoned to a failover, its handle
evicted, or its device revoked or deregistered — finished runs' uncollected
work included, because nothing a revoked device sent is landed afterwards; and,
for work nobody collects, 15 minutes after its run ended, checked on each
heartbeat. Never when a session detaches: the handle outlives the link, and in a
hub cluster other members still track the run. The budget belongs to the
executor rather than to a session, so a device that reconnects — rehydration runs
on every handshake — finds the bytes it left still counted.

A revoke from the dashboard also removes the executor from the hub member that
served it. Other members drop it when the deletion reaches them over the cluster
bus, which does not deliver a member's own events back to it.

The level is in `cloop_writeback_pinned_bytes` and `cloop_writeback_pinned_bytes_max`,
refusals in `cloop_writeback_frame_refusals_total`; see
[the metrics](../operations/metrics.md#returned-work-held-in-memory).

### `kubernetes` — Kind `kubernetes`, isolation `remote`

One ephemeral Pod per workload: `generateName`, `restartPolicy: Never`, no
long-lived identity. `Start` creates the Pod and returns; a watcher goroutine
follows phase transitions and opens the log API with `follow=true` once the Pod
is Running. `Signal` is Pod deletion — which means `SignalInterrupt` arrives in
the container as SIGTERM, because kubelet only ever sends TERM then KILL.

The Pod spec forces `runAsNonRoot`, a read-only root filesystem, all
capabilities dropped, `seccompProfile: RuntimeDefault`, and
`automountServiceAccountToken: false`. The kubeconfig comes from a
[secret broker lease](../guides/secrets.md#kubeconfig), is held in memory for the
handle's lifetime, renewed while running, and released on a terminal state — it
is never written to the hub's disk. This is the hub acting as itself, so it is
deliberately *not* routed through the
[Kubernetes access monitor](kubernetes-access.md): that monitor governs the
kubeconfigs delivered **into** a sandbox, and a read-only policy in front of this
one would stop the hub creating Pods at all.

There is no bind mount here, so `/workspace` starts empty and the source tree
arrives by way of a `workspace` init container — see
[Workspace provisioning](#workspace-provisioning). Anything that reads a
container status by name must therefore keep selecting `harness` rather than
"the only one".

The project itself — `.cloop/`, which a clone of the source repository does not
contain — comes with the run, and its outcome goes back: the hub's seed rides
the run's lease Secret into the init container, and what the run recorded comes
home as a framed block at the end of the Pod's log. A repository needs no
`.cloop/` committed, and a task a Pod finished shows finished on the dashboard.
See [Kubernetes: the seed in a Secret, the outcome in the log](#kubernetes-the-seed-in-a-secret-the-outcome-in-the-log-task-20402).

`executors.kubernetes.runtime_class` sets `runtimeClassName` on every Pod, and
is how a **remote Kata sandbox** is requested: kube-scheduler places the Pod on
a node advertising that handler and the workload boots in a VM with a kernel of
its own, on a machine that is not the control plane's. Isolation stays `remote`
— that fact has not changed — and `Virtualized` becomes true alongside it. The
class must already exist in the cluster; cloop does not create one, and it is a
cluster-scoped object an operator installs with the Kata node pool. Because
those pools are conventionally tainted, this key normally appears with
`tolerations` and `node_selector`. The name is validated as an RFC 1123
subdomain at startup rather than at dispatch, so a typo is an error against the
config line that caused it instead of a 422 on somebody's first run
(`ValidateRuntimeClass`, `kubernetes/validate.go`).

Unlike the container driver there is **no preflight check** for it. A
RuntimeClass is a cluster-scoped object, and the hub holds a namespaced Role in
the workload namespace and nothing else — it cannot read one, by design. A
mis-set class therefore surfaces at dispatch, as a Pod that never runs and a
rejection naming the class it asked for.

---

## Sandbox network isolation

Two backends run workloads that have a network, and until recently neither
constrained what that network reached. The container driver's package comment
said *"it does not filter egress"* and meant it: `Network` was either `none` —
no interfaces at all — or a runtime network with unrestricted outbound access.
The Kubernetes driver set a `cloop.dev/egress` label and admitted beside it that
the label was documentation, because a Pod joins the pod network and no field in
a Pod spec takes that away. The
[egress broker](../reference/configuration.md#scoped-network-egress) bound a
workload that honoured `$HTTP_PROXY` and nothing else.

`pkg/netfilter` closes that with **one compiler and several renderers**.
`Compile` turns an authorisation into an ordered, first-match-wins `Policy`
ending in an implicit drop; the backends render that same `Policy` as an
`nft(8)` script or as a Kubernetes `NetworkPolicy`. `Evaluate` answers "what
would this policy do to that packet" with no backend at all, which is what lets
a test compare the filter against the proxy address-by-address rather than
trusting that two hand-written rule sets agree. The package depends on nothing
but the standard library, so every driver can reach it without dragging the
broker's storage and crypto along.

### `Capabilities.FilteredEgress`

```go
NetworkEgress  bool // can workloads reach the network at all?
FilteredEgress bool // is what they reach bounded by a policy cloop installs?
```

They are two fields because they answer two questions and conflating them loses
both. `NetworkEgress` says whether the workload has an interface, which is what
[placement](#placement) needs — `RequireNetworkEgress` and the `network_egress`
rejection reason read it. `FilteredEgress` says whether what it reaches through
that interface is constrained, which is what an operator auditing a fleet needs.
A sandbox can have the first without the second, and that combination is exactly
the thing worth being able to find.

`false` does not mean "nothing filters this". A cluster may run its own
`NetworkPolicy` and an operator may firewall the host; it means *cloop* is not
the thing doing it and will not claim credit for it. Both drivers report it from
their `egress_filter.enabled`.

What it does **not** report is whether the filter is effective. On Kubernetes a
`NetworkPolicy` is applied by the CNI, and whether the cluster runs one that
implements it is not something the API answers — so the field says what cloop
installed, and the preflight `egress` finding carries the caveat. Nothing in
placement requires the field; it is a report, not a constraint.

### The container driver: two mechanisms

Which one applies is decided by the *shape* of the authorisation rather than by
a separate switch. An `egress_filter` that names only `internal` gets the first;
one that names CIDRs, resolvers, a broker endpoint or the public Internet gets
both.

**An `--internal` runtime network.** The runtime installs no route off the
bridge, so nothing on it reaches the Internet at all. Put the egress broker on
the same network and it becomes the only way out — which is what turns the
broker's host allowlist from advisory into enforceable. This needs no
privileges, no `nft` and no `CAP_NET_ADMIN`, and it is the strongest option
because the layer-3 filter and the layer-7 allowlist then describe the same set.

**A host-side nftables ruleset scoped to the sandbox bridge**, for the case
where the authorisation names addresses the sandbox must dial directly — a
Kubernetes API server, an internal registry. The table is `inet` rather than a
separate `ip` and `ip6` pair, because two families mean two rulesets that can
drift and a v6 ruleset an operator forgot is the whole firewall bypassed by a
AAAA record. The script is fed to `nft -f -` on stdin, which nft commits as one
transaction: either the sandbox is filtered by the entire policy or the start
fails. `add table` / `delete table` / `table` makes a re-apply replace rather
than accumulate, which is the property a reconcile loop needs. Teardown of a
table that is already gone is success.

Two things about the bridge form are worth knowing before reading one:

- **Both the `forward` and the `input` hook carry the rules.** The routing
  decision picks the hook — destinations the host forwards on take `forward`,
  destinations belonging to the host itself take `input` — so a ruleset with
  only a `forward` chain filters the Internet and leaves the host wide open.
  See the [threat model](../security/threat-model.md#vulnerabilities-found-while-building-this).
- **The chain policy is `accept`, not `drop`.** Base chains on the same hook all
  run and a drop in any of them kills the packet, so a `policy drop` chain here
  would take down every other container on the host. Each chain instead returns
  immediately for traffic whose `iifname` is not this sandbox's bridge, and ends
  with an explicit `drop` that only packets from that bridge can reach.

**Why the filter is installed host-side rather than inside the namespace.** A
workload that starts before its filter exists has a window of unrestricted
egress. The obvious approach — start the container, find its PID, `nsenter` into
its namespace, install rules — has no ordering guarantee at all. Filtering on
the host side removes the window structurally: the bridge exists from the moment
the network is created, and network creation is strictly before any container
can join it, so the rules are always in place first. `installFirewall` runs
before the image is even resolved, and its failure fails the `Start` — producing
a working sandbox with none of the requested filtering, silently, is worse than
refusing to run.

The network is derived from the executor id (`cloop-sbx-<id>`), not accepted
from config, which stops two differently-filtered executors from pointing at one
bridge where the second apply would silently replace the first's rules. It also
means the policy is per executor: every sandbox that executor starts joins the
same bridge under the same ruleset. Enabling the filter makes the driver stop
using the configured `Network`, because an operator-named network could be
shared with workloads this executor does not manage and a default-deny ruleset
on their bridge would firewall them too.

### The Kubernetes driver: a NetworkPolicy per Pod

`RenderNetworkPolicy` translates the same compiled `Policy`, and the translation
is not mechanical, because the two models differ where it matters. A `Policy` is
ordered and has both verdicts; a `NetworkPolicy` is an unordered union of allows
with no deny rule at all. So the drops become `ipBlock.except` entries and the
ordering becomes set arithmetic: "allow the public Internet" becomes `0.0.0.0/0`
with every blocked prefix excepted, and "a granted CIDR waives the block that
covers it" becomes a second peer for that CIDR — peers are a union, so the
granted prefix is allowed even though the Internet peer excepts the range
containing it. Peers are grouped by port signature rather than emitted one per
rule, because within a single egress rule peers and ports form a cross product
and a granted CIDR on 6443 alongside the Internet on 443 would otherwise each
acquire the other's ports.

Three details follow from the object model rather than from the policy:

- The `podSelector` must match exactly the Pod it governs — an empty selector in
  Kubernetes means *every* Pod in the namespace — so the driver selects by the
  unique handle-id label and the renderer refuses an empty selector outright.
- `policyTypes` names `Ingress` with no ingress rules. Omitting the type would
  leave inbound ungoverned; naming it with no rules is what denies it.
- Cluster DNS is opened as a `namespaceSelector` on `kube-system`, not as an
  address. The Service ClusterIP is in private space and which side of the
  policy the CNI applies its DNAT on varies by CNI, so the selector is the form
  that works everywhere. It is on by default, because a default-deny egress
  policy without it breaks name resolution and that failure reads as "the
  network is broken" rather than "DNS is denied".

The namespace-local rules — the sandbox's own loopback — are dropped by this
renderer rather than emitted as a meaningless `127.0.0.0/8` peer, since a
`NetworkPolicy` never sees traffic that does not reach a wire.

What this renderer cannot promise is enforcement. A `NetworkPolicy` is inert
unless the cluster runs a CNI that implements it; flannel does not, and the API
server accepts the object regardless. That is a fact about the cluster which
cloop cannot read out of the API, so it is a standing `egress-enforcement`
preflight warning rather than a claim. Managing the objects also needs
`networkpolicies: [create delete list]` on the executor's Role, and preflight
lists them to prove the leased identity really has it — a `403` there is a
`fail`, because every `Start` will refuse rather than run a Pod with unfiltered
egress.

### Reaching the hub's egress proxy: `Spec.EgressProxy`

A run whose project holds an egress grant is issued a session on the proxy the
hub hosts (Task 20378, [Scoped network egress](../reference/configuration.md#scoped-network-egress)),
and the session's URL goes into the workload's environment, declared sensitive.
What the hub cannot do from where it stands is make the address in that URL
reachable: which bridge a container lands on, and so which gateway the host
answers at, is the engine's; what a sandbox's firewall lets through is decided
when the driver compiles it. So the Spec carries a route, and the driver
finishes it:

```go
type EgressProxyRoute struct {
    Host    string // the host the proxy URL names
    Port    int
    Gateway bool   // pin Host, inside the sandbox, to its bridge's gateway
}
```

It carries no credential, so it is safe to persist and to send to a device.

| Executor | Route the hub chooses | What the driver does with it |
| --- | --- | --- |
| host process | the bound address | nothing: the workload is on the host |
| container (hub's engine), proxy on every interface | `host.containers.internal`, `Gateway: true` | `--add-host host.containers.internal:<gateway>` for the bridge the sandbox joined, ahead of any operator pin; when a ruleset is installed, the gateway and port added to it as an allow, TCP only |
| container, proxy on one host address | that address | the address and port added to a ruleset |
| Kubernetes | `advertise_addr` | nothing: the hub has already proven, with `netfilter.Evaluate`, that the Pod's policy allows it |
| remote agent, virtual executor | `advertise_addr` | a v18 agent's container driver does what the hub's does; a v17 one is given no session behind a firewall |

Two consequences for the container driver. The proxy is opened in the compiled
`Policy` itself — `provisionNetwork` asks the policy's own `Evaluate` whether the
sandbox reaches `gateway:port` before anything is installed, and refuses the
start when an operator deny list covers it, rather than start a sandbox holding
a session it cannot use. And a ruleset that opens the proxy is a different
ruleset from one that does not, so the proxy's port joins the confinement key:
such sandboxes get a bridge and a table of their own (`cloop-sbx-<id>-…-x<port>`),
and the second apply can never close the first's way out. An `--internal` bridge
with no ruleset needs no opening — its gateway is on-link — so its sandboxes
keep sharing one bridge.

### Seeing what a policy compiles to

`cloop egress firewall` renders the policy without touching a host, in the same
text the driver installs — see
[the command reference](../reference/commands.md#cloop-egress-firewall). An
operator can diff it against `nft list table inet cloop_sbx_<id>` on the host or
`kubectl get netpol -o yaml` in a cluster, and `--check <addr:port>` answers the
one-address question with the verdict in the exit status.

---

## Registry and binding

`pkg/executor/registry.go` answers one question: *which executor runs work for
this project?*

```
Registry.Resolve(projectPath)
  → in-memory binding      (Bind, set from the UI/CLI)
  → persistent lookup      (SetBindingLookup → statedb, survives restart)
  → default executor       (the first one registered, or SetDefault)
  → policy check           (refuse isolation=none under strict mode)
```

Project paths are canonicalised — absolute and `filepath.Clean`ed — but symlinks
are deliberately *not* resolved, because the binding must match what the
operator typed in the config, not where the filesystem happens to point today
(`registry.go:302-311`).

`Resolve` fails closed in both directions: an unknown project with no default is
an error, and a resolved executor that offers no isolation under strict mode is
a `*HostExecutionDeniedError` carrying the list of isolated alternatives so the
UI can render a fix rather than a dead end.

### Who may use an executor

`Resolve` answers *which* executor, never *for whom* — it is handed a project
path and no identity, and it is called from contexts that legitimately have
none (the CLI, the failover supervisor, a scheduled run continuing after the
person who started it went home).

So an executor's access list is enforced one layer up, at the two HTTP requests
where a human actually chooses an executor:

| Request | Gate |
| --- | --- |
| `POST /api/projects/{idx}/executor` | refuses the binding |
| `POST /api/run` | refuses the run |

The run gate is the load-bearing one. An admin may narrow an access list after
a project was bound, and a binding made yesterday must not outlive the access
it was made under.

An executor with **no** access-list entries is unrestricted — which is every
executor until an admin adds the first one, and is what makes the feature a
no-op for existing deployments. Adding the first entry is the act that turns
the gate on, so the API refuses an add that would leave the calling admin
unable to use the executor they just restricted (`executor_audience_self_lockout`).

Entries are matched against OIDC claims by `pkg/authz`'s own binding matcher,
so a group path (`/platform-team`) and the bare name are interchangeable
exactly as they are in role bindings. Note that this is a *gate*, not a grant:
role bindings are additive and cannot express "everyone except", because the
permission being restricted is one the caller already holds fleet-wide.

Managing an executor and being allowed to use it are separate rights. An admin
can restrict a device they cannot themselves run work on; the panel says so
rather than letting them discover it at the next run.

### How much one workload may be given

Three ceilings compose, widest scope to narrowest, and each can only *lower*:

| Source | Set in | Answers |
| --- | --- | --- |
| `fleet` | `executors.limits` in config.yaml | what any workload on this hub may have |
| `executor` | `PUT /api/executors/{id}/limits` | what any workload **on this device** may have |
| `project` | per-project, operator-set | what this one project may have |

The executor ceiling exists because neither of the others can express it. The
fleet's applies everywhere, so writing the weakest device's capacity there holds
the whole fleet down to it; the project's is set before anyone knows which
executor the work will land on.

`BoundSpec(spec, projectPath, executorID)` applies all three and returns a
`Clamp` per reduction naming the source, so a developer told their run was
capped can tell whether to ask the hub admin, the device's admin, or nobody.
`pkg/executor/ceiling.go` documents why a ceiling never fills in a limit the
project left unset: doing so would convert "stated nothing" into "explicitly
requested the ceiling", which the drivers treat as more specific than their own
configured default — so the ceiling could *raise* an allowance.

The drivers fill it in instead, after resolving their own default: the container
driver bounds `--cpus`, `--memory`, `--pids-limit` and the workspace's disk limit
by `CeilingFor` in `buildRequest`, and the Kubernetes driver fills an unset Pod
limit. A device reads no ceiling of its own, so the remote driver fills the
device's (or virtual executor's) ceiling into the spec it dispatches when the
device runs payloads in a container — the disk one only to an agent at protocol
v20 or later, since an older one's container driver refuses any disk limit
(`MinDiskLimitVersion`, Task 20405).

**Disk** is the resource a driver can enforce, or not, independently of the
others, so it has a capability of its own: `Capabilities.DiskEnforcement` is
`sampled` (the container driver, on the hub or on a v20 device, which measures
the workspace and stops a workload that outgrows it), `eviction` (Kubernetes),
or empty. A spec stating `resources.disk` requires it at placement
(`RequireDiskLimit`, constraint `disk_limit`), and a disk ceiling in force on an
executor without it is reported by `CeilingUnenforceable` on every dispatch,
clamp or no clamp — it exists for the project that asked for nothing. How the
container driver measures, and what a stop records, is in
[`resources.disk` and the workspace](../reference/sandbox.md#resourcesdisk-and-the-workspace).

---

## Placement

`Registry.Resolve` picks the executor for a *project*. `pkg/executor/placement.go`
picks one for a *workload* out of a fleet — used on failover, and by any caller
that expresses requirements rather than a binding.

`Select(candidates []Candidate, req Requirements) (Candidate, error)` is a pure
function: no I/O, no clock, no registry. That is what makes fleet behaviour
testable.

A `Candidate` carries the executor plus its scheduling context: `Health`,
operator `Labels`, detected `Harnesses`, `ContainerRuntimes`, `MemoryMB`, and
in-flight count. `Requirements` can pin `ExecutorID`, demand `Labels`,
`Harnesses`, `Platform`/`Arch`, `MinMemoryMB`, `RequireIsolation`,
`AllowedIsolations`, `RequireVirtualization`, `RequireKernelIsolation`, and
capability flags (`RequireStream`, `RequireSignal`, `RequireContainerRuntime`,
`RequireNetworkEgress`, `RequireResourceLimits`, `RequireImageOverride`,
`RequireSandboxBuild`, `RequireSandboxMounts`, `RequireHostMounts`,
`RequireDevices`, `RequireEgressScope`, `RequireWorkspaceProvisioning`,
`RequireHostFilesystemWorkspace`, `RequireWriteBack`).

`RequireVirtualization` is separate from `AllowedIsolations` because it cuts
across it. Both a local Kata container (`vm`) and a Kata Pod on a cluster
(`remote`) satisfy it, and no set of `Isolation` values selects exactly those
two without also admitting every non-Kata remote executor that shares the second
one's value. It is checked against `Capabilities().Virtualized`, which is why
that field is false unless the driver is certain: a workload that must be behind
a hypervisor lands on one that is not the moment something claims otherwise.

`RequireImageOverride`, `RequireSandboxBuild` and `RequireSandboxMounts` come
from a project's
[`.cloop/sandbox.yaml`](../reference/sandbox.md). They exist so that a
per-project sandbox spec cannot be *silently* ignored: a project pinning
`image: rust:1.79` placed on a driver with no image concept would run against
whatever toolchain the host happens to have, produce a plausible-looking build
failure, and send its author hunting through their own code. Refusing placement
and naming the constraint points at the deployment instead. Every field a driver
can quietly drop has a flag that says whether it does.

`RequireHostMounts` is the same argument again, but the request comes from a
*grant* rather than from a repo-committed file: a
[`local_repo`](../guides/secrets.md#local-git-repositories) grant binds
directories from the control-plane host into the sandbox at `/repos`, and
`Capabilities().SupportsHostMounts` is whether this driver can do that at all.

| Driver | `SupportsHostMounts` | Why |
| --- | --- | --- |
| `container` | ✅ | it runs on the hub and has a mount namespace to bind into |
| `localprocess` | ❌ | shares the hub's filesystem, so there is nothing to bind — the granted repositories are already visible at their own paths |
| `kubernetes`, `remote` | ❌ | the workload runs on a machine that has never seen those files |

It is deliberately **not** implied by `SharesHostFilesystem`, and the middle row
is why the two are different answers rather than one: a driver needs both to run
here *and* to have a namespace to bind into, and `localprocess` has only the
first. A driver that ignored the field would start a harness whose `/repos` is
empty, which is the failure this constraint converts into a refusal that names
the grant and the binding.

`RequireDevices` and `RequireEgressScope` are the same argument for the two
capabilities that are about what the *host* can do rather than what the transport
can carry. `Capabilities().SupportsDevices` is whether a driver can expose a host
device node inside the sandbox, which a
[`host_device`](../guides/secrets.md#host-devices) grant asks for;
`Capabilities().SupportsEgressScope` is whether it can confine one workload's
IP-layer egress *independently of the other workloads on the same executor*, which
`capabilities.egress` in a project's
[`.cloop/sandbox.yaml`](../reference/sandbox.md) asks for.

| Driver | `SupportsDevices` | `SupportsEgressScope` | Why |
| --- | --- | --- | --- |
| `container` | ✅ | ✅ | it runs on the machine with the hardware and the runtime takes `--device`; and a scope gets a bridge and an nftables table of its own, which this driver provisions |
| `kubernetes` | ❌ | ⚠️ once enforcement is proven | Kubernetes takes no device paths — a device plugin hands the container whichever unit it has free. Egress *is* confined per run, by a `NetworkPolicy` selecting one Pod by its unique handle-id label — but a `NetworkPolicy` is applied by the cluster's CNI, so the capability is advertised only once enforcement is [proven or asserted](#does-the-cluster-actually-enforce-a-networkpolicy) |
| `remote` | ❌ | ❌ | a device path names the *hub's* host, and the agent runs each workload as a plain process, so there is neither a sandbox to put a device into nor a per-workload network namespace to filter |
| `localprocess` | ❌ | ❌ | the workload is a process in the hub's own namespaces: every device the hub user can open is already open to it, and confining its egress would mean filtering the control plane's own traffic |

Two notes on why these are refusals rather than best-effort.

`SupportsDevices` is not implied by `SupportsHostMounts`, because a device is not
a file a driver can bind and be done with: a container runtime needs a cgroup rule
permitting the `major:minor` pair as well as the node itself, and the Kubernetes
driver needs the node to advertise the hardware at all. `HostDevice` carries a
`KubernetesResource` field for the extended-resource shape that driver would need;
it is deliberately unconsumed rather than approximated with a `hostPath`, since
mounting `/dev/nvidia0` from whatever node the scheduler picked would expose an
unrelated piece of *that* node's hardware — worse than refusing. A driver that
dropped the field would produce a sandbox whose `/dev` is missing exactly the
hardware the task exists to talk to.

`SupportsEgressScope` cannot be best-effort for a sharper reason: its absence is
silent *and* over-permissive. An executor that ignored a project's request to be
cut off from private address space would hand the harness the reach into the
operator's internal network the project had explicitly renounced, and report
success doing it. `container` advertises it unconditionally rather than gating on
`egress_filter.enabled`, because the whole point of a scope is that a project can
ask to be confined on an executor whose default is unfiltered; a host without
`nft(8)` fails at install time with a message naming it.

### Does the cluster actually enforce a NetworkPolicy?

The Kubernetes driver is the one case where cloop does everything right and the
result can still be nothing.

`pkg/executor/kubernetes/networkpolicy.go` compiles a `NetworkPolicy` per run
from the same `pkg/netfilter` policy the container driver's nftables ruleset is
compiled from, selecting that Pod alone by its unique `cloop.dev/handle-id`
label, and `Start` creates it *before* the Pod it governs — a Pod that started
first would have a window of unfiltered egress, and a window is all an
exfiltration needs.

None of that matters if the cluster's CNI does not implement `NetworkPolicy`.
flannel is the well-known case: the API server validates the object, persists
it, returns `201`, and nothing ever reads it. `kubectl get netpol` lists a
firewall that does not exist. **The Kubernetes API cannot be asked which case you
are in**, so cloop refuses to guess:

| Evidence | Status | `SupportsEgressScope` |
| --- | --- | --- |
| nothing | `unverified` | ❌ — placement refuses, naming the probe |
| `network_policy_enforced: true` | `asserted` | ✅ on the operator's word |
| a probe proved it | `proven` | ✅ |
| a probe refuted it | `refuted` | ❌ — and preflight reports a **fail** |
| `network_policy_enforced: false` | `denied` | ❌ |

Precedence is deliberate and is the security argument:

1. An explicit `false` wins outright. It is the restrictive direction, and it is
   the only control that takes effect *immediately* — the alternative would be
   editing config and then racing a recorded verdict still inside its expiry.
2. A fresh probe beats an assertion **in both directions**. An operator who
   asserted enforcement on a cluster that demonstrably ignores policies has made
   a mistake, and the measurement is what catches it.
3. An assertion beats nothing.
4. Nothing is `unverified`, and `unverified` fails closed.

A verdict expires after 30 days (`DefaultVerdictMaxAge`), because a CNI can be
replaced by a platform team that has never heard of cloop; an expired one is
treated as absent rather than as evidence against anything. A verdict recorded
for a *different* executor is ignored outright — executors differ in namespace
and in the credential they connect with, and a `NetworkPolicy` is namespaced.

#### The probe

```
cloop hub doctor --probe-network-policy [--executor k8s] [--probe-image …]
```

It is the only `hub doctor` check that writes to the cluster, which is why it is
opt-in. In the executor's own namespace it creates:

1. a **target** Pod serving one byte over HTTP;
2. a **control** client Pod that fetches it with no policy in place — this must
   **succeed**;
3. a **policed** client Pod carrying a label a default-deny egress policy
   selects, fetching the same address — this must **fail**.

Step 2 is what makes it a proof rather than a coincidence, and it is the step an
obvious implementation leaves out. Without it, "the client could not connect" is
indistinguishable from "the target never came up", "the image has no `wget`",
"the node is wedged", or "the namespace already denies everything" — and every
one of those would be recorded as *enforcement*, which is the exact false
confidence the mechanism exists to prevent. A control that does not succeed
yields `ErrProbeInconclusive` and **no verdict in either direction**.

The probe's Pods take the executor's `image_pull_policy`. Where that is `Never` —
a kind cluster with images loaded by hand, as CI's is — the default
`busybox:1.36` is not on the node, the target never starts, and the probe reports
*inconclusive* only when its timeout runs out. Pass `--probe-image` an image the
nodes already hold that provides `sh`, `httpd` and `wget`;
[`tests/kube`](../../tests/kube/README.md) uses its harness image, alpine with
`busybox-extras` (Task 20385). On CI's kind cluster the probe **refutes**
enforcement on every run: its CNI accepts the policy and the policed Pod still
connects. So CI creates and removes a per-Pod policy there, and does not assert
that one bites.

The connection attempt is the Pod's command and the result is its exit code read
from Pod status, so the probe needs no `pods/exec` RBAC — exactly the `pods` and
`networkpolicies` verbs the egress filter already requires. Every object is
registered with a janitor *before* its create is attempted (a create that times
out may still have landed) and removed on a detached context from a deferred
call, so a probe interrupted by Ctrl-C, a timeout or a panic still cleans up. A
leftover default-deny policy in a shared namespace is an outage for whatever is
scheduled there next.

The verdict is stored in the hub's control-plane database and pushed onto the
live driver, so it takes effect without a restart *and* survives one. An
in-cluster `ConfigMap` was rejected: it would make this feature's bookkeeping
require `configmaps` RBAC the executor does not otherwise hold, and a security
capability that fails closed when its bookkeeping is unauthorised trains
operators to widen the Role until the warning goes away.

#### Sweeping what it leaves

Every per-run policy is deleted with its Pod, and `ReconcileOrphans` collects any
that a control-plane restart stranded — using the same label selector and grace
period as the Pod sweep. The grace period matters in the opposite direction here:
deleting a Pod too eagerly kills a run, while deleting a *policy* too eagerly
unfilters one that is still running.

The sweep runs whenever the executor `createsNetworkPolicies()`, which is true
for a configured `egress_filter` **or** a scope-capable executor. The second half
is not redundant: an executor with `egress_filter.enabled: false` and a proven
CNI still creates a policy for any project that asks for one, and a filter-only
guard would strand one per interrupted run. Probe objects carry the sweep's
labels for the same reason — a probe killed with `SIGKILL` runs no deferred
cleanup, its Pods carry `activeDeadlineSeconds`, and nothing in Kubernetes ever
expires a `NetworkPolicy`.

`RequireWorkspaceProvisioning`, `RequireHostFilesystemWorkspace` and
`RequireWriteBack` are the same argument applied to the source tree, and the
first two pull in opposite directions: one demands a node that *can* fetch, the
other one that does not have to. `RequireWriteBack` asks whether the files the
task changed can be returned at all. See
[Workspace provisioning](#workspace-provisioning).

`CheckSandboxSupport(ex, req, projectPath)` runs the *bound* executor through
this same `reject()` as a candidate list of one, so a constraint added to
`Select` is enforced on the binding path for free rather than drifting from it.

Ranking, applied as a stable sort:

1. Ready before degraded
2. More free capacity first — fills the fleet evenly rather than hot-spotting
3. Isolated before un-isolated — prefer a sandbox when both would satisfy
4. Executor ID alphabetically — deterministic tie-break

**There is no fallback.** When nothing matches, `Select` returns a
`*PlacementError` carrying the headline `Constraint`, a per-candidate
`Rejection` list, and how many candidates were considered. Constraints are
named: `no_candidates`, `executor_id`, `health`, `host_execution_policy`,
`isolation`, `virtualization`, `kernel_isolation`, `labels`, `platform`, `arch`,
`harness`, `container_runtime`, `network_egress`, `resource_limits`,
`disk_limit`, `stream`, `signal`, `memory`, `capacity`, `image_override`, `sandbox_build`,
`sandbox_mounts`, `host_mounts`, `devices`, `interfaces`, `egress_scope`, `workspace`,
`write_back`, `secret_files`, `revocation`, `agent_build`. An operator asking
"why did nothing schedule?" gets a per-node answer, not a shrug.

`virtualization` is the one whose message names the two config keys that fix it,
because the candidate is otherwise healthy and correct: it "shares the executing
machine's kernel", which is the normal state of a container or a plain Pod, and
the remedy is a line of hub configuration rather than anything about the node's
health, labels or capacity.

`kernel_isolation` is its weaker sibling and exists because conflating the two
costs real placements. It asks only that the workload's syscalls are not served
by the executing machine's kernel, which gVisor's Sentry satisfies without a
hypervisor — so a project whose actual requirement is "a kernel bug in my task
must not be a kernel bug on the host" can say that, instead of demanding a VM and
watching every `runsc` node in the fleet get rejected for a property it had
provided. Every virtualized executor is also kernel-isolated; the reverse does
not hold, and the gap between them is exactly gVisor.

`interfaces` is `devices` narrowed twice over, and the second narrowing is the
one that surprises people. A `host_interface` grant needs an executor on the
machine the interface is attached to, like a device grant — and it additionally
needs a runtime whose kernel will *notice* a link that appears after the sandbox
has started. A Kata guest kernel and a gVisor Sentry both build their view of
the network when the sandbox starts, so on those runtimes the move succeeds, the
host loses the interface, and the workload sees nothing. That is worse than any
refusal, so the capability is false there and placement says why. See
[Hardware and network devices](../guides/enterprise-hosts.md#4-hardware-and-network-devices).

`devices` and `egress_scope` are the two whose refusal is about *where* rather
than about a missing feature. A `host_device` grant names hardware on one
machine, so a project holding one and bound to a Kubernetes or remote executor
has asked for something no retry will produce; `egress_scope` needs a driver that
can confine one project's egress independently of its neighbours, which means a
bridge and an nftables table of its own. Both name the alternative rather than
degrading: the first says which executor to bind to, the second says to enable
`executors.container.egress_filter` on a host with `nft(8)` or to drop the key
and inherit the executor's own policy. See
[critical hosts as executors](../guides/enterprise-hosts.md).

Two of those names describe the request rather than any node. `no_candidates`
means the registry was empty — nothing was rejected because there was nothing to
reject, which is a deployment problem and not a matching one. `executor_id`
means the workload was pinned to a specific executor and that executor was not
among the candidates; a pin is a statement about *where*, never a licence to run
on a node that is dead or that policy forbids, so a pinned workload is still
checked against every other constraint.

`workspace`, `write_back` and `secret_files` are the constraints
`CheckSandboxSupport` deliberately does *not* fold into a host-policy denial.
Every other capability gap on an un-isolated node reads as "bind this project to
a sandbox"; for these three that advice is exactly backwards, because the bound
executor is already isolated and that is precisely why it cannot see the tree,
return the diff, or open the hub's lease directory.

`secret_files` deserves its own note, because the failure it prevents is the
quietest one in the list. An executor that cannot receive a secret lease's
credential *files* still receives its environment — so the workload starts
holding `GIT_CONFIG_GLOBAL` and `CLOOP_LEASE_DIR` pointing at a directory that
does not exist on that machine, and, for a repository-scoped `github_pat`, no
token at all (see [Secret file delivery](#secret-file-delivery)). The run
succeeds in every observable way except the one that mattered. Refusing
placement is the only point at which anything can name the cause.

`revocation` is the same shape of failure one level up, and it is the reason
the constraint exists at all. A driver that cannot take a lease back still
starts the workload and still delivers the credential — it simply has no way to
withdraw it, so the lease TTL and the push revocation become advice on that
backend. Because nothing observable changes, the gap is invisible until an
operator revokes a credential during an incident and it keeps working.

The constraint is answered by the driver implementing `executor.Revoker`, not
by a capability flag. The two would drift, and the direction they would drift
in is a backend advertising a guarantee it does not implement. A new driver
therefore opts in by writing the code; until it does, every workload carrying a
brokered credential is refused there by name. See
[Revocation per backend](../security/model.md#revocation-per-backend).

`agent_build` is the only constraint that is not about a capability at all. Every
other entry asks whether a node *can* do something; this one asks whether the
cloop build it is running is recent enough to be trusted with the work.

It exists because the negotiated protocol version cannot express most of what
changes between builds. The protocol number moves only when a frame moves, so two
devices can both speak the current protocol and differ by a year of fixes to
things the wire never sees — a workspace cleaned up wrongly, a credential not
wiped, a signal not forwarded. An operator who has deployed such a fix had no way
to stop scheduling onto the devices that predate it, and found out which ones
those were from the failures.

The floor is set once, fleet-wide, with `executors.min_agent_build` (see
[configuration](../reference/configuration.md#execution-backends-executors)), and applied as a
ratchet: a hub reads many tenants' `config.yaml`, so a tenant-controlled file
must not be able to lower it. It is read inside the shared rejection path, which
means `Select` and `CheckSandboxSupport` honour it identically — a floor enforced
on only one of the two would be a floor with a bypass.

A device that *cannot prove* it meets the floor is refused along with one that is
genuinely older, and the message distinguishes them, because the fixes differ: a
device reporting no build at all predates build-version reporting, one reporting
the placeholder `1` is a build from before agents knew their own version, and one
reporting an unreleased `dev+g…` build carries nothing that can be ordered
against a release. Setting a floor is a request for devices that can substantiate
their build, not for devices that decline to answer.

Container, Kubernetes and local-process executors are never subject to it. They
run the control plane's own binary, so there is no separate build to compare, and
treating them as "build unknown" would take every sandbox out of the fleet the
moment a floor was configured.

Build currency is also a *ranking* input, below capacity and above the ID
tie-break: among otherwise-equal nodes, the newer build wins. Ranking it above
capacity would pile a fleet's whole workload onto whichever device was upgraded
most recently; leaving it out entirely means a stale device keeps taking work
because it happens to sort first alphabetically, and nothing ever surfaces that
it is stale.

The remedy named in the message is `cloop executor agent install --upgrade`, which
is safe to run against a critical host: it executes the staged binary before
replacing anything and restores the previous one if the service does not come
back. See [Upgrading a device](#upgrading-a-device).

One subtlety worth knowing: a node that advertises *no* harnesses passes the
harness requirement. Empty means "detection failed", not "has none" — treating
it as a hard rejection would strand every node whose probe hadn't run yet.

---

## Workspace provisioning

`Spec.WorkDir` names a directory. For a long time nothing said how the project's
source tree was supposed to get *into* it, and only one backend had an answer:
`container` bind-mounts the host path, so the tree was already there. Kubernetes
mounted an empty `emptyDir` — its own comment conceded the workload was
"expected to populate it" — and the remote agent `MkdirAll`'d a directory
beneath its root. Nothing populated either.

That is a bad failure because it does not look like one. The run starts cleanly,
the harness finds an empty directory, and the model writes a confident report
about a repository it never read. Nothing in the hub's view distinguishes it
from a real run — no error, no exit code, no missing artifact.

So every dispatched `Spec` now carries an explicit `Workspace`, and there are
exactly five answers to "where does the code come from":

| `Kind` | Meaning | Chosen when |
| --- | --- | --- |
| `bind` | the tree is already at `WorkDir`; the executor is looking at the same filesystem the hub is | `Capabilities().SharesHostFilesystem` |
| `git` | the executor fetches it before the harness starts | the project is a checkout with a fetchable https remote |
| `executor` | the directory belongs to the executor and is kept there between runs; only the project's state crosses | the project is not a git repository at all |
| `bundle` | the executor builds it from a git bundle the hub ships beside the Spec, leaving the checkout on the shipped branch | a feature runs on an executor that isolates from the hub, and its branch cannot be shipped as commits on top of a `git` clone ([Features](#features-shipping-a-branch-task-20367)) |
| `none` | the workload genuinely wants an empty directory | the workload has no project at all (the voice handler runs `cloop listen --file …`) |

### Projects with no repository of their own (Task 20324)

`executor` exists because demanding a git remote was demanding the wrong thing
of a legitimate project shape — and the common one for this product. A project
here is a *unit of work*; its code is whichever repositories have been
[granted](../guides/secrets.md) to it, which the harness clones for itself once
it is running — authenticating with the credential helper its lease installs,
or through the [git proxy](../git-interception-proxy.md) where the hub runs one.
Such a project's own directory holds `.cloop/` and little else, and there is
nothing useful to fetch from it.

The harness is told which repositories those are. A GitHub lease announces its
allowlist and access level in `CLOOP_GITHUB_REPO_ALLOWLIST` and
`CLOOP_GITHUB_PERMISSIONS`, and `cloop run` turns them into a *Repository
access* section of the task prompt: the repositories, whether a push will be
accepted, how to clone them, and that work committed but not pushed stays on
the device. Without it an agent asked to "commit it to the repo" finds no
repository in its working directory, runs `git init` there, and reports a
commit nobody will ever see — which is what the first end-to-end run on a real
edge device did (Task 20337).

Before this, the hub refused those dispatches outright, telling the operator to
`git remote add origin …` and push a directory with no source in it.

What crosses instead is `Spec.ProjectSeed` and nothing else — the goal, the
instructions and the plan, with the step history dropped (see
[`pkg/executor/projectseed`](https://github.com/blechschmidt/cloop/blob/main/pkg/executor/projectseed/projectseed.go)).
That is typically a few hundred bytes to a few hundred kilobytes, against a
source tree that is not sent at all. Three consequences are worth stating
plainly:

- **`WorkDir` names a path on the executor, not on the hub.** It is
  `DeviceWorkDir(<hub path>)` — a stable name derived from the hub's project
  path — resolved beneath the agent's own `--workdir-root`. The hub's absolute
  path never becomes a path the device is asked to open.
- **The directory is kept.** The name is deterministic and the agent does not
  wipe it, so a repository cloned by one task is still there for the next. This
  is the one kind for which `WorkspaceKind.KeepsWorkDir()` is true. What is
  *not* kept is the previous dispatch's `.cloop/state.db`: writing the seed
  removes it, so the run loads the plan as the hub has it now. Merely being
  newer than it was not enough — `cloop run` opens the project database before
  it compares the two — and a task reset on the hub stayed failed on the device.
  Nothing is lost by removing it: the run that wrote it sent its outcome back
  when it ended ([below](#the-project-comes-back-task-20339)).
- **The seed is mandatory, not best-effort.** On a `git` workspace `.cloop/` may
  already be committed in the fetched repository, so a seedless executor merely
  degrades. Here nothing is fetched, so a seedless executor would start the
  harness in a directory with no project — `SandboxRequirements()` therefore
  derives `RequireProjectSeed` from the *kind*, and such an executor is refused
  placement.

A project that *is* a git repository but has no usable remote keeps refusing,
and that distinction is deliberate: it has local history that an executor-owned
workspace would silently leave behind on the hub. Only the total absence of
`.git` takes this branch.

Kubernetes refuses `executor` outright. A Pod's working tree is an `emptyDir`
that dies with the Pod, so it cannot keep the promise the kind makes. It can be
seeded (Task 20402), so the refusal comes from the driver rather than from the
seed gate, and says so: give the project a git remote, or bind it to a remote
agent, which keeps a working directory.

The zero value is `""` — *unspecified* — and leaves a driver's pre-existing
behaviour alone. It exists so a caller with no workspace concern (`cloop
executor test`, a smoke run) is not forced into a declaration it has no basis
for. `none` is not the same thing: it is a statement that an empty tree is
intended, which is what stops an empty tree being confused with the bug.

**A `bind` driver must never clone.** `WorkDir` on the container and host
drivers is the *operator's own checkout* — the working tree they have open in an
editor, with uncommitted changes in it. A provisioner that ran there would
`git init` over it, fetch, and check out a detached `FETCH_HEAD`, discarding
work that exists in exactly one place. This is why `SupportsWorkspaceProvisioning`
is `false` on those drivers as an *answer* rather than a gap, and why
`Workspace.Validate()` refuses a `bind` spec that also carries a `Repo`: a spec
with a harmless extra field and a spec whose author believes a clone will happen
are indistinguishable at the point where it matters.

### Per-driver matrix

| Driver | `SharesHostFilesystem` | `SupportsWorkspaceProvisioning` | Gets | How |
| --- | --- | --- | --- | --- |
| `localprocess` | ✅ | ❌ | `bind` | forks in the operator's own directory |
| `container` | ✅ | ❌ | `bind` | `--volume <project dir>:/cloop/work` |
| `kubernetes` | ❌ | ✅ | `git` | a `workspace` init container, before the harness container starts (`executor` is refused: an `emptyDir` cannot be kept) |
| `remote` | ❌ | ✅ *if* the device has `git` on `PATH` **and** speaks protocol ≥ 3 | `git` | a pre-step on the device, before it hands the Spec to its inner host driver |

Kubernetes reports `true` unconditionally, including when no secret broker is
wired in. What the capability advertises is that the driver *materialises the
tree* — which it does, with no broker at all, for a public repository. Gating it
on a credential source would refuse a public clone at placement time for want of
a credential it does not need; a missing grant deserves the typed error below,
not a message about a capability.

The remote row is the interesting one. An older agent would accept the start
frame, ignore the workspace, and run the harness in the empty directory it
created — the exact failure, on a machine the operator cannot see. So the hub
refuses the *dispatch* rather than trusting the device to complain, and the
refusal names the device and the upgrade.

### How the hub decides

`pkg/ui/workspace.go` is the single place a `Workspace` is chosen, and it runs
after the sandbox spec is applied and before dispatch. For a `git` workspace it
reads the project's own `.git/config` and `.git/HEAD` **without running git** —
`pkg/ui` may not spawn processes at all (a control plane that can fork can only
ever run work as itself), and `git remote get-url` would apply the *ambient*
configuration anyway: an `insteadOf` rewrite left on the hub by whoever last
touched it would silently choose a different clone URL.

- The origin remote is normalised to `https://`. The scp form every forge prints
  (`git@host:owner/name.git`) and `ssh://` URLs are rewritten; `http://`,
  `git://`, `file://` and bare local paths are refused by name. This is not a
  preference: the credential travels as an `Authorization` header, which over
  cleartext is a published token, and over ssh there is nothing the broker can
  lease at all.
- The ref is the branch `HEAD` points at. A detached `HEAD` yields an empty ref,
  which means the remote's default branch — the commit a hub happens to be
  parked on is not necessarily reachable by a fetch, and inventing a ref that
  then fails is a worse error than starting from the default.
- Userinfo in the URL is stripped rather than refused. The URL still names the
  right repository, and the grant is where the authority is supposed to come
  from.
- A project on a non-sharing executor with **no usable git remote** is refused,
  naming the project, the executor and both fixes (give the project an https
  remote, or bind it to an executor that shares the host filesystem). That
  refusal *is* the feature: the tree cannot be materialised, so the run must not
  start.

The grant is selected from broker *metadata* — `ListGrants` plus `ListSecrets` —
not by taking a lease. A lease unseals every matching payload and writes an
audit row per grant, and this decision needs one string: the grant's name. The
matching mirrors `LeaseFor` exactly (same requester shape, same active-grant
rule, same repository allowlist) because a grant chosen here that `LeaseFor`
would not produce is a Spec that fails at dispatch with a worse error. When
several grants admit the repository the newest wins, which is the one an
operator who has just created a grant expects.

Two cases fetch anonymously rather than refusing: a repository URL that is not
`owner/name` (a GitLab subgroup, say) cannot be matched against an allowlist at
all, so no grant could ever authorise it; and an install with no secret broker
configured has simply not adopted it yet. In both, a public repository works and
a private one fails inside the fetch with git's own authentication error —
neither outcome is a silent empty tree.

### The mechanism

Both drivers run the *same engine*, `pkg/executor/gitprovision`. Two
implementations of "how cloop clones a repo into a sandbox" would be two chances
to reintroduce the bug, and the second copy would drift silently — the symptom
of a drifted provisioner is a run that looks fine.

The plan is `git init` → `remote add` → `fetch` → `checkout --detach
FETCH_HEAD`, not `git clone`. `clone --branch` can only name a branch or a tag,
while a fetch can name any ref including a bare commit SHA; a provisioner that
worked for `main` and silently failed on a pinned commit is the sort of thing
discovered in production. `Workspace.GitPlan` renders that sequence as a pure
function — no I/O, no clock, no environment — which is what lets both callers
emit the same commands and lets a test assert on them without a git binary.

**Kubernetes** renders an init container named `workspace` whose argv is exactly
[`cloop workspace provision`](../reference/commands.md#cloop-workspace-provision).
Four choices there each had a plausible alternative:

- It uses the **harness image**, not a git image. A second image would need its
  own registry-allowlist entry, its own digest pin and its own trip through the
  [image trust policy](../reference/sandbox.md#image-trust-policy) — three places
  for the provenance of the thing that handles a credential to diverge from
  everything else.
- It provisions into `workDir`, not into `/workspace`. When a Spec puts the
  harness in a sub-directory of the workspace volume, cloning into the volume
  root would leave the harness's actual directory empty: the original bug, one
  level down.
- It does **not** inherit `Spec.Env`. The harness's environment carries brokered
  provider keys; a git fetch has no business with any of them, and the narrower
  the environment the fewer places a hostile repository's hooks can reach.
- Its `securityContext` is built by the same function as the harness's, so the
  two cannot drift. An init container with one capability more than the harness
  would be a way to do privileged work in a Pod that reads as hardened.

**The remote agent** runs the engine as a pre-step in `prepareWorkspace`, bounded
at 30 minutes (a first clone over an edge uplink is legitimately minutes; the
bound exists because a fetch stalled on a half-open connection would otherwise
hold a handle forever). Provisioning output goes into the workload's own
retained buffer, so it reaches the run's live log through the same
offset-acknowledged path as the harness's output — including across a reconnect.
Afterwards the agent rewrites the workspace to `bind` before handing the Spec to
its inner host driver, which is the literal truth at that point: the tree is now
on the machine that is about to run.

The engine also owns the parts a pure plan cannot express:

- **An existing checkout is reused, never re-initialised.** Same origin: fetch
  and check out, which is also much cheaper on a slow uplink. Different origin:
  a refusal naming both URLs, because re-cloning would discard whatever is
  there.
- **Rollback is asymmetric.** A failed provisioning removes the partial
  repository only if this machine created it; files that were in the directory
  beforehand are left alone, because deleting what we did not create is
  unrecoverable.
- **The size limit is enforced, not advertised.** `resources.disk` from
  [`.cloop/sandbox.yaml`](../reference/sandbox.md#resourcesdisk-and-the-workspace)
  is checked immediately after the fetch — the earliest point an oversized
  repository is visible — and again after the checkout. On a machine with no
  runtime quota there is nothing between the fetch and the filesystem except
  this check, and the disk being filled belongs to whoever owns the machine.
- **The environment is closed, not inherited.** A fetch that read the machine's
  `~/.gitconfig` could pick up a credential helper, an `insteadOf` rewrite
  pointing it at another host, or a proxy — all chosen by whoever last touched
  that box rather than by the grant. The one allowed exception is transport
  (`HTTPS_PROXY`, `NO_PROXY`, `SSL_CERT_FILE`, `GIT_SSL_CAINFO` and their
  siblings), because an edge device behind a corporate proxy with a private CA
  is precisely the machine that cannot otherwise clone, and none of those
  variables can name a repository or supply a credential. `GIT_SSL_NO_VERIFY` is
  pointedly absent. So is the rest of the machine's `GIT_CONFIG_COUNT` block,
  except the certificate settings scoped to an https URL —
  `http.<url>.sslCAInfo` and `.sslCAPath` — which is how a Pod's provisioner
  trusts the git proxy's private CA without replacing its trust store for every
  other host ([`git_ca_bundle`](../reference/configuration.md#on-kubernetes-the-git-proxys-ca-for-its-url-only),
  Task 20385).

Provisioning writes two audit rows of its own — `start` before the first byte
moves, `end` once, with the duration and the outcome — because it is the moment
a brokered credential is used against an external service, and the run's own
record cannot answer "which grant fetched which repository onto which executor".
Both rows name the grant and lease IDs; neither can carry material.

### The credential

Covered in full in [the security model](../security/model.md#workspace-provisioning).
The architectural shape: a `Spec` carries the *name* of a grant, the driver
dispatching the workload leases the material at the last possible moment, and it
reaches exactly one child process — the single `fetch` step, marked
`Authenticated` in the plan — as a URL-scoped `http.<base>.extraHeader` in its
environment.

What a driver leases is an `executor.WorkspaceAccess`: the credential **and** the
repository URL that credential is good against, which `Apply` writes onto the
workspace before anything is rendered. With no interception the URL is empty and
`Apply` changes nothing. With the
[git interception proxy](../git-interception-proxy.md) enabled the credential is
an ephemeral session token and the URL is the proxy's, so the fetch and the
write-back push both aim there and the forge PAT never leaves the hub. The two
travel together on purpose — a driver that took the credential and ignored the
URL would send the sandbox at the forge holding a token the forge has never heard
of, which fails immediately rather than quietly restoring the direct path.

Which copy of the workspace is rewritten differs by driver, and deliberately so.
The Kubernetes driver routes the workspace the Pod is built from, so the init
container's fetch, the checkout and the push all agree. The remote driver routes
only the *shipped* Spec: the persisted and audited copy keeps naming the real
repository, because an operator reading a run row wants `github.com/acme/tool`,
not a proxy URL whose session died with the run. `container` and `localprocess`
never reach this path at all — they bind the operator's own checkout and provision
nothing. Their workloads' own git still reaches the proxy, through a GitHub lease
rather than a workspace; [git proxy architecture](git-proxy.md) covers both
paths and what each backend contributes to them. On Kubernetes the init container
authenticates to the proxy with the session id, which the run's workspace Secret
carries beside the token.

A workspace whose fetch nobody can authorise fails with a typed
`*executor.WorkspaceGrantError` that names the repository, the grant and the
executor, and whose `Remediation()` prints the `cloop secret grant` command that
fixes it. The alternative — a bare "missing credential", or worse, a run against
an empty tree — is what this whole subsystem exists to remove. The Web UI
renders that remediation directly, as HTTP 409 `workspace_grant_missing`.

`Spec.Validate()` additionally refuses `Kind: git` together with
`DisableNetwork`. A tree that must be fetched and a workload forbidden from
reaching the network is a contradiction, and the failure it produces otherwise —
"could not resolve host", from a step nobody knew ran — points nowhere near the
two settings that caused it.

### Kubernetes RBAC consequence

The chart's executor Role gained two verbs: `create` and `delete` on `secrets`
in the workload namespace — and later a third, `patch`, with which a running
Pod's lease Secret has a GitHub App token replaced before GitHub's hour ends
(Task 20375; see [replacing a file under a running workload](#replacing-a-file-under-a-running-workload)). Deliberately **not** `get`, `list` or `watch` — the
driver writes the per-run Secrets, points the Pod at them with `secretKeyRef`s
and volumes, and deletes them; the workspace credential as soon as the init
container terminates. It never reads a Secret back, so it holds none of the read
side.

The whole Role is one table in the driver — `executorRole`, in
`pkg/executor/kubernetes/rbac.go` — and every RBAC remedy the driver prints is
rendered from it. `TestHelmChartExecutorRoleIsExactlyWhatTheDriverCalls` renders
the chart with `helm template` and requires its Role to match the table in both
directions, and CI's kind job checks every verb on every resource with
`kubectl auth can-i` against the installed release. Before both, the only check
asserted the Pod verbs: an added `patch` on `networkpolicies` — the authority to
widen a running sandbox's firewall — would have shipped.

It is worth being precise about why this does not widen the namespace's blast
radius, because it is the objection anyone reviewing the change will raise
first. With `pods: create` plus `pods/log: get` — both of which this identity
already had — any Secret in the namespace can already be read by mounting it
into a Pod and printing it. That is one `kubectl run` equivalent, and it was
true of every previous release of the chart. **The namespace has always been the
boundary**; `create` and `delete` on Secrets does not move it. What would move
it is a ClusterRole, or a rule in the release namespace where the hub's own
credentials live, and neither exists.

What the rule buys is that no credential ever appears in a Pod spec — not the
workspace token, and since Task 20401 not the workload's environment either
(see [the environment, on Kubernetes](#the-environment-on-kubernetes)). Without
it, the only ways to get a token into a container are an `env` value or an argv
element, and both publish it to everyone with `get pods`, to every `kubectl
describe`, and to the API server's audit log. There is no `update` or `patch` on
Pods or NetworkPolicies, so a compromised hub cannot rewrite a running
workload's spec or widen its firewall; the one `patch` the Role holds replaces a
GitHub App token in a lease Secret's files.

A hub without the rule fails at `Start` with a 403 that prints the exact YAML to
add.

This used to carry an honest gap: a control plane killed between creating the
Secret and observing the init container finish left the Secret behind, named
`cloop-ws-<handle>`, and nothing swept it — sweeping needs `list secrets`, which
this driver deliberately does not hold.

Task 20281 closed it without taking that read access. Both per-run Secrets carry
an `ownerReferences` entry naming the Pod that consumes them, so the cluster's
own garbage collector deletes them when the Pod goes: deleted by the driver, by
the orphan sweep, by a node eviction, or by an operator with `kubectl`. Setting
an ownerReference on create needs no verb beyond the `create` already held, so
the Role is unchanged — and `blockOwnerDeletion` is deliberately left false,
because setting it true would make the `OwnerReferencesPermissionEnforcement`
admission plugin demand `update` on `pods/finalizers`.

That is why the Secrets are created *after* the Pod rather than before it. An
ownerReference needs the owner's UID, the API server assigns it, and a client
cannot choose one — so no ordering lets a Secret created first name the Pod that
comes second. The Pod is unscheduled in the gap and the kubelet cannot resolve a
`secretKeyRef` before the scheduler has bound it, so losing that race costs a
kubelet retry rather than a run.

The **NetworkPolicy is the exception, and stays unowned.** It has to exist
*before* the Pod — a Pod that starts before its policy has a window of
unfiltered egress — so there is no ordering that gives it both a UID to name and
a guarantee of preceding the workload. Attaching one afterwards would need
`patch` on `networkpolicies`, which is also the authority to widen a running
sandbox's firewall, and is the one verb this Role must never grant. It does not
need one: unlike a Secret, a policy *is* listable by this driver, so the orphan
sweep collects it — which is why the same task made that sweep periodic instead
of startup-only.

---

## The tree is not the project: seeding `.cloop/` (Task 20316)

Everything above gets the *source tree* onto the executor. A cloop project is
not only a source tree: it is also `.cloop/` — the goal, the instructions, the
provider and effort selection, and the plan. The hub holds all of that in its
own `.cloop/state.db`, and for a long time nothing carried any of it across a
dispatch.

The dispatched argv is `cloop run`, and that process reads `.cloop/` from the
directory it is standing in. On a `bind` workspace that directory *is* the hub's
project, so this was invisible. On a `git` workspace it is a fresh clone of a
source repository, which contains no cloop project, so the run exited on its
first line with:

```
Error: no cloop project found (run 'cloop init' first)
```

The only way to make a remote or Kubernetes run work at all was to commit
`.cloop/state.db` — a live, WAL-backed SQLite file — into the repository. That
is not a workaround a product can ship: it publishes the plan to everyone who
can read the repo, it is a binary blob the sandbox then rewrites, and it is
silently truncated unless the author remembers to `PRAGMA wal_checkpoint`
first.

So a `git` workspace now carries the project with it.

| | |
| --- | --- |
| Field | `Spec.ProjectSeed []byte` (`json:"-"`) |
| Format | gzip-compressed JSON in the legacy `.cloop/state.json` shape |
| Built by | `projectseed.Build`, from `state.LoadLite` |
| Placed by | `projectseed.Write`, into `<workspace>/.cloop/state.json` |
| Capability | `supports_project_seed` |
| Wire | `StartPayload.ProjectSeed`, protocol **v10** |
| Ceilings | 4 MiB compressed, 32 MiB inflated |

**Why the legacy `state.json` shape.** It is not a new format: it is the one
`state.Load` already migrates from on every open. The sandbox side therefore
needs no new code at all — the first `state.Load` finds a `state.json` and no
`state.db`, migrates, and returns a populated project through the import path
every legacy project on disk has exercised for a year. It also fixes a second
bug for free: a reused work directory on an edge device kept the *previous*
dispatch's `state.db`, so the next run read stale state and reported every task
already complete without running anything. A freshly written `state.json` is
newer than that database, which is the migration's second trigger, so the stale
state is replaced rather than believed.

**What a seed deliberately leaves out.** Step history, which is the overwhelming
majority of a long-running project's state and none of which the sandbox needs —
this is what keeps a 482-task plan in the hundreds of kilobytes. And `WorkDir`,
which is cleared: it is the path `Save` writes back through, so a seed carrying
the hub's absolute path would aim the sandbox's writes at a directory on another
machine. The far side re-derives it from wherever it is migrating.

**What a seed carries instead of the config.** `.cloop/config.yaml` never
travels — it can hold API keys, and credentials reach a sandbox only through
[grants](../guides/secrets.md). Two of its choices a run cannot do without, so
the hub resolves the provider and model exactly as it does when it picks the
harness to prepare (config, then state, then the default) and writes them into
the seed's state. On the far side `cloop run` finds no configuration of its own,
and in that one case the project's recorded choice outranks `Default()`'s —
before Task 20339 it did not, and every seeded run was a `claudecode` run
whatever the project had chosen. A flag, `CLOOP_PROVIDER`, a profile or a real
config file still win, exactly as before.

**The payload names no destination.** Nothing inside a seed influences where it
lands; the receiving side always writes `<workspace>/.cloop/state.json` inside
the directory it has already confined. A seed that carried its own path would be
an arbitrary-file-write primitive aimed at whichever host materialised it — the
same reasoning that makes `SecretFile.Name` a bare file name below.

**Why `json:"-"`, like `Spec.SecretFiles`.** Different motive, same rule. Secret
files are excluded because they are plaintext credentials; a seed is excluded
because it is *large and reconstructible*. `pkg/executorstore` persists the
dispatched Spec, the audit trail echoes it, and reconcile re-reads it after a
restart — a few hundred kilobytes of plan written to three places on every
dispatch would undo the control plane's own retention work. A wire format that
needs the bytes opts in explicitly.

**This one capability degrades instead of refusing placement**, and that is the
deliberate exception to the rule the rest of this page follows. Every other
capability gap is a refusal, because a workload needing something the executor
cannot do is a workload that will fail. A seed is different: *every*
project-scoped run carries one, so making it a requirement would refuse every
dispatch to every pre-v10 agent in a fleet — including the installations that
work today by committing `.cloop/` into the repository, which was the only way
this path worked before. A fix for a broken flow must not break the workaround
people adopted because it was broken. A capable executor gets the seed; an older
one behaves exactly as it does today and the project's journal gets a
`project_seed` row naming the executor and the upgrade.

`Spec.SandboxRequirements()` still derives `RequireProjectSeed` from the field,
so a *future* caller that attaches a seed without checking the capability is
refused rather than silently dropped.

**Kubernetes is seeded too (Task 20402).** Until then the Pod driver reported
`supports_project_seed` false and took the degraded path above, so a Kubernetes
executor needed `.cloop/` committed to the repository. The seed now travels as a
key of the run's lease Secret, projected into the `workspace` init container
alone, and `cloop workspace provision --seed` places it after the checkout —
see [Kubernetes: the seed in a Secret, the outcome in the
log](#kubernetes-the-seed-in-a-secret-the-outcome-in-the-log-task-20402). The
`project_seed` journal row's remedy now fits the executor's kind: only a device
is told to upgrade an agent.

---

## The project comes back (Task 20339)

A seed carries the project *out*. For a long time nothing carried it back, and
the consequence was the one an operator reported: start the project on the sgx
device, watch the transcript end with *All tasks complete*, and find the task
still pending on the dashboard — "immediate completion although there is one
remaining task". The run had done the work. It had recorded the outcome in its
own copy of the project, on the device; the dashboard renders the hub's copy,
which nothing ever updated. Starting it again ran the task again, and the agent
found its own work already pushed and skipped it.

So when a seeded workload exits, the device reads back what the run changed and
sends it, and the hub merges that into its own copy before it settles the run.

| | |
| --- | --- |
| Built by | `projectseed.Harvest`, on the device, from the workspace's `.cloop/state.db` |
| Merged by | `projectseed.Merge` / `Apply`, on the hub, from `runEnded` |
| Wire | `project_result` frame, protocol **v13**, sent before the terminal status |
| Capability | `returns_project_state` |
| Ceilings | 640 KiB compressed, 16 MiB inflated; step output shrinks first |
| Journal | one `project_result` row per seeded run, whatever happened |

**What travels is the change, not the project.** The device compares the run's
database with the seed it was sent and returns every task whose record differs
— with both versions — every task the run created, and the run's steps, journal
events and cost rows. The last three are new by construction: a seed carries
none, and the previous dispatch's database was removed before the run began. A
500-task plan in which one task finished returns one task.

**The device reads the database, not the run's say-so.** A run killed half way
reports nothing, but the tasks it finished before it died are in its database,
and those are exactly the work that would otherwise be lost. The read is
confined like everything else the agent does in a workspace: exactly
`<workspace>/.cloop/state.db`, never through `active_session`, `session.json` or
a legacy `state.json` the workload could plant, and never through a symbolic
link.

**Ordering is the write-back's.** After the harness exits, because only then is
the database final; before the terminal status, because that frame closes the
hub's log stream and `runEnded` settles the run the moment it closes. A reading
that could not be delivered is kept and re-sent after the next reconnect.

**The hub's copy is the authority.** The result is a report from the least
trusted party in the system about work done out of the hub's sight, and the
hub's copy may have moved on meanwhile. So the merge takes the run's word only
where the run is the one that knows:

- A task's **outcome** — status, summary, timings, counters, notes — is taken
  as a unit, and only while the hub's outcome for that task is still the one it
  sent. A task the operator reset, skipped or finished by hand while the run was
  out keeps the operator's outcome, and the journal row says so.
- Everything else about a task the hub already has — title, description,
  priority, dependencies, condition, schedule, approval — is never read from a
  result.
- A task deleted on the hub while the run was out stays deleted. One whose ID
  now names a different task — the hub reuses IDs, which is exactly what the
  operator above had done before the run — is left alone.
- A task the run created is added, renumbered if the hub has since used its ID,
  with only what a plan entry needs. A condition is a shell command, a
  recurrence a schedule, an approval an authorisation; none of them survives.
- **Where the run executed is the hub's to say.** Tasks are stamped with the
  executor, isolation and run id of the hub's own dispatch. The device writes a
  placement record beside the seed so its run no longer believes it ran as a
  bare local process — which is what every remote task's notes used to claim —
  but the hub does not rely on it.
- **Spend is billed to whoever the hub billed the dispatch to**, priced from the
  hub's table where it knows the model, and recorded through the ledger so it
  reaches the global budget exactly as a run on the hub would.
- Free text is scrubbed of the credentials the hub leased to the run, on the
  hub, with the same set that scrubs the live log.

**A run that ends mid-task is recovered, not believed.** Its result says the
task is in progress and the project running; both are merged, and dead-run
recovery — which `runEnded` runs straight afterwards — requeues the task and
pauses the project with the executor's account of how the run ended. The one
exception is a task whose outcome the run had already decided when it ended —
the review gate failed it, a verification rejected it, its background work
never finished — but not yet stored. The orchestrator writes that decision to
the task's verdict sidecar first, and the device applies it before reading the
run back, so the hub hears "failed by the review gate" rather than "in
progress", with the recovery in the journal. The device reads only the
sidecars for this, refuses symbolic links in their path, and writes nothing.
A run that finished the plan it was sent while the hub's plan grew is paused as
*idle* rather than marked complete.

**This one degrades rather than refuses, like the seed.** A v10–v12 agent runs a
seeded project correctly and cannot report the outcome. Refusing it placement
would turn a stale dashboard into no remote runs at all until every device
upgraded, so instead the project's journal gets a `project_result` row naming
the executor and the upgrade. The rule that is enforced runs the other way: an
agent never sends the frame on a session below v13, because an older hub has no
handler for it.

**A hub restarted mid-run (Task 20382).** A hub that restarts while a device
is running a seeded task — :8888 restarts nightly — no longer loses the run. The
dispatch record the merge needs is the run's owner row (`hub_owners`, Task
20354), which carries the executor, the handle, the provenance a result is
merged under and, for a feature, what its returned work lands against; it
survives a graceful stop and a SIGKILL alike. The new process rehydrates the
handle, the agent reconnects and offers it back, and the process adopts the run:
it streams it, merges its result once — one `project_result` row, its cost rows
booked once — lands a feature's commits fast-forward or keeps them on
`cloop/returned/…`, and settles it. What the dispatching process held only in
memory is taken over too:

- **The run's secret lease.** Leases are recorded in `secret_leases` (ids and
  names, never values) under the hub process holding them, and the owner row
  names the run's lease. The adopting process takes it over — the same lease id,
  extended from then on by its keepalive, listed in its Secrets panel, released
  by it when the run ends — and re-derives from the lease's grants the values it
  scrubs from the run's output (env secrets and personal access tokens; a GitHub
  App token is left to the pattern scrubbers, which recognise its shape). A lease
  that lapsed, or whose grants were withdrawn, while no hub held it is taken back
  from the device instead, and the leader's lease janitor sweeps one whose holder
  never came back once it lapses.
- **What the lease feeds (Task 20383).** The run's git proxy and Kubernetes
  monitor sessions are recorded in `proxy_sessions` (token hashes and scopes,
  never a credential) and restored in the adopting process under the ids and
  tokens the workload holds — their scope held to what the grant and the hub
  allow now, their upstream credentials re-derived from the lease, a GitHub App
  token minted afresh at its recorded scope. The App token slots recorded in
  `app_token_slots` come with the lease, so a token delivered as a file is
  renewed before its hour by the new holder's keepalive. The run's egress session,
  named in the owner row, is restored with its byte counters, so its quota keeps
  binding. A session whose grant was revoked or expired meanwhile is closed with
  the reason instead; nothing in a record decides where a credential goes — the
  upstream is the hub's own, an App token's repositories are re-checked against
  the grant. See [a hub restarted mid-run](git-proxy.md#a-hub-restarted-mid-run).
- **The run's executor session.** The restart sweep leaves a device's session
  open until its agent reconnects, and the adopting process watches it to its
  end, so it records how the run ended and stays visible to failover meanwhile.

`tests/e2e/hubrestart_test.go` stops a real hub with SIGTERM and with SIGKILL
under a real agent and checks all of the above, for a plain project and for a
feature; `tests/e2e/hubrestart_proxies_test.go` does the same to a hub running
the git proxy and the Kubernetes monitor, whose device workload pushes through
the restored git session and reads a cluster through the restored monitor
session after the restart. Helper subcommands dispatched to a device (`cloop reset` from the
dashboard) are still not merged: they are not runs, and a reset expressed as a
diff would not reset anything the diff cannot name.

### Kubernetes: the seed in a Secret, the outcome in the log (Task 20402)

A Pod shares nothing with the hub and talks to nobody: its ServiceAccount token
is not mounted, and its `/workspace` is an `emptyDir` that dies with it. So
until Task 20402 the Kubernetes driver reported neither `supports_project_seed`
nor `returns_project_state`, and the hub dispatched anyway. A repository with
no `.cloop/` committed produced a run that exited on its first line with *no
cloop project found*; a repository *with* it produced a run whose finished
tasks were recorded only in the Pod's copy, so the dashboard still showed them
pending and the next Start ran them again. Both capabilities are now true, and
`pkg/executor/kubernetes/projectresult.go` is the code.

**In: a key of the lease Secret, read by the init container alone.**

| | |
| --- | --- |
| Carried in | the run's lease Secret, `cloop-lease-<handle>`, under the key `project-seed`, beside the run's credential files and environment |
| Projected into | the `workspace` init container only, read-only, at `/run/cloop/seed/seed.gz` (a Secret volume naming that one key) |
| Placed by | `cloop workspace provision --seed /run/cloop/seed/seed.gz --seed-copy /run/cloop/dispatch/seed.gz`, after the checkout: `projectseed.Write`, as the remote agent does, then `gitprovision.HideControlDir` |
| Baseline copy | `/run/cloop/dispatch/seed.gz`, a 2 MiB `emptyDir` the init container writes and the harness mounts read-only — what the run's changes are measured against afterwards |
| Ceiling | the Secret's whole data — keys and values of the credential files, the environment and the seed — at most 1 MiB, the API server's limit for a Secret |

The three channels that look simpler are each refused. An argv or a value in
`env` is readable by every identity with `get pods` in the namespace, printed
by every `kubectl describe` and written to the API server's audit log, and a
project's instructions and plan are the operator's, not the namespace's. A
ConfigMap is the same object without the handling a Secret gets — the kubelet
does not keep it on tmpfs — and the executor's Role has no `configmaps` rule at
all, by design.

**The 1 MiB ceiling is Kubernetes-specific.** `projectseed` itself allows 4 MiB
compressed; a Pod can carry whatever room is left in its lease Secret once the
credential files and the environment are in it. A run whose seed does not fit
is refused by `Start` before anything is created in the cluster, and the
refusal names the project's state, its size and the room it had, and the two
ways out: archive finished tasks (`cloop task archive`), which shrinks the plan
and therefore the seed, or bind the project to a remote agent, which takes the
full 4 MiB. A plan big enough to reach it has hundreds of finished tasks in it.

**A placed `.cloop/` is never committed.** The push write-back runs `git add
--all` (`pkg/executor/gitwriteback`), and so may the harness. The init container
therefore excludes `/.cloop/` in the checkout's `.git/info/exclude` and marks
every file the repository tracks under it skip-worktree — the treatment a
shipped feature branch gets (`gitprovision.HideControlDir`) — so the project's
state database cannot reach the `cloop/` branch and, from there, the
repository. The remote agent applies the same exclusion to a seed it places into
a `git` checkout, which it had not done either.

**A seed supersedes a committed `.cloop/`.** This is a behaviour change for an
installation that worked around the gap by committing `.cloop/` into its
repository. Placing the seed removes the committed `state.db` from the working
tree before writing the hub's project, exactly as it does on a device, and the
skip-worktree mark keeps both the removal and the seed out of the commits. The
run therefore sees the hub's project, not the repository's copy of it: a task
edited, reset or added on the hub is what runs, and a plan committed to the
repository is ignored. The committed copy can be deleted from the repository;
nothing reads it any more.

**Out: a frame at the end of the log.** The harness container's command is
`cloop workspace writeback --dir /workspace --seed /run/cloop/dispatch/seed.gz
--project-result-frame <handle> -- <argv>` — the push write-back's flags too,
when one was asked for. Once the harness has exited the wrapper reads back what
the run changed (`projectseed.Harvest`) and prints it as the **last** thing on
stdout, after the write-back's own report, as a
[`pkg/executor/resultframe`](https://github.com/blechschmidt/cloop/blob/main/pkg/executor/resultframe/resultframe.go)
block:

```
##cloop-project-result-v1## <handle> begin result <length> <sha256>
##cloop-project-result-v1## <handle> data <base64, 3072 characters a line>
…
##cloop-project-result-v1## <handle> end
```

Each line is one `write(2)` of under 4 KiB — below `PIPE_BUF`, so a line can be
preceded or followed by another process's line in the container log but never
cut by one. The frame is preceded by an empty line, which ends anything the
workload left unfinished on the same stream. A run whose state cannot be read
back gets a frame of kind `error` carrying the reason instead, so the hub can
say why rather than that nothing came.

**The driver lifts the frame out before anybody reads the log.** Every chunk the
log follower reads goes through the record's frame scanner before the log bus:
the frame's lines never reach the live log or the run's artifact — they are
protocol, up to a megabyte of base64 — and everything else is forwarded
unchanged, a line held back only while it could still turn out to be a frame
line. A line closing the log says what came back: *read the run's project state
back from pod …* or *no project result came back from pod …* with the reason.

**What the hub accepts from a Pod is what it would accept from a device.**

| | |
| --- | --- |
| Result ceiling | 640 KiB (`executor.MaxProjectResultBytes`), refused on the frame's declaration before a byte is kept |
| Reason ceiling | 4 KiB (`executor.MaxProjectResultErrBytes`), the bound a device's `project_result` frame has |
| Accepted for | a seeded run only — a frame in an unseeded run's log is somebody's text and passes through untouched |
| Accepted when | whole: the declared length, the SHA-256 and an end line all match, and nothing else bearing the handle's tag was seen before or after |
| Otherwise | `executor.ErrProjectResultUnavailable` and no bytes — truncated (the log ended inside the frame), interleaved (a second begin inside the first), duplicated (a second frame, or a line of one, after the first ended), unframed (data or end with no begin) |
| Handed over | once, by `ProjectResult`; a second call is unavailable, because merging a run twice books its spend twice |
| Scrubbed | the result by the hub with the run's redaction set, as for a device; a refusal's reason by the driver before it reaches the journal, since it can quote a line the workload printed |

Lines that are not the frame's may sit between the frame's own — the runtime
merges stdout and stderr line by line, and the wrapper writes progress to
stderr — and leave it intact. Lines tagged with another handle (a fixture
printed by a run working on cloop itself, a nested run's frame) are transcript.

**The workload shares that stream, and it does not matter.** It can print a
frame bearing the right tag, but the wrapper's real frame always follows the
harness's exit, so a forged one makes the pair a duplicate and neither is
believed: a workload can deny itself its own result, which corrupting its own
database would do as well. And the content of a result is the workload's to
shape on every transport — a device reads it out of the database the workload
wrote — which is why [the merge](#the-project-comes-back-task-20339) treats every
result as the least trusted party's account and takes the run's word only for
outcomes.

**Memory.** A result is held from the end of the Pod's log until the hub
collects it, which for a run is the same moment: `runEnded` settles a run the
instant its stream closes. A result nobody collects — a helper subcommand's,
whose outcome the hub does not merge — is bounded: past 32 MiB per executor the
oldest uncollected one is dropped, and a collector that turns up after all is
told so.

**A hub restarted mid-run.** The handle's durable row records `project_seed`,
and an adopted Pod's log is re-read from its start, so the frame is found
whether it was printed before the restart or after it; the run's owner row
carries the provenance the merge needs, as for a device.

**The harness image must carry this release's cloop or later.** The init
container and the wrapper run the image's own `cloop` (the path the harness's
argv names, else `cloop` on `PATH`). An older one fails the init container with
`unknown flag: --seed`, and the run fails as *the workspace could not be
provisioned, so the harness never ran*. The Helm chart's
`executor.kubernetes.image` defaults to the hub's own image, which carries the
same cloop; an image built for real tasks has to be rebuilt on the hub's
release.

**What it changes on the journal.** A `project_result` row about a run that
sent nothing back now names what goes wrong for that kind of executor and the
driver's own account — for a Pod, a log that ended without a complete frame and
why — instead of a device's dropped connection; and no row tells a Kubernetes
executor to upgrade an agent it does not run. **Features stay refused** on
Kubernetes: shipping a feature's branch needs a channel from the hub into the
Pod that holds a bundle, and a 1 MiB Secret is not one; nor can a log carry a
bundle back.

`pkg/executor/kubernetes/projectresult_test.go` covers the Pod's shape, the
Secret ceiling and the round trip against the fake API server, including every
malformed frame; `pkg/executor/resultframe` has unit tests and two fuzz targets
(`FuzzScanner`, `FuzzRoundTrip`, in `make fuzz`); and
[`tests/kube`](../../tests/kube/README.md) runs a project whose repository has
no `.cloop/` on CI's kind cluster and checks that the hub's plan shows its task
done afterwards and that a second Start does not run it again.

---

## Features: shipping a branch (Task 20367)

A [feature](../guides/features.md) is a linked git worktree on the hub, and its
`.git` names the parent repository by an absolute host path, so the worktree
itself cannot travel. Until Task 20367 a feature was therefore refused on every
executor that isolates from the hub — which, on a hub with
`executors.allow_host_process: false`, is every executor. Mounting the parent's
`.git` into the sandbox to make the pointer resolve was never an option: hooks
and configuration written there run on the hub at the next git command run in
that repository.

Instead a feature travels as its branch.

| | |
| --- | --- |
| Shipped | `Workspace.Branch` (`executor.BranchBundle`): the branch, its head, the bundle's size and SHA-256, and for a shallow slice its boundary commits. On a `git` workspace pinned at the feature's base it is the feature's own commits (an *overlay*); on a `bundle` workspace it is the whole branch, or its newest 50 commits, or its newest one. The bytes ride beside the Spec — `Spec.BranchBundleFile` on the hub — never in it. |
| Built by | `pkg/executor/featurehub.Ship` on the hub; `gitprovision` on the executor, always into an emptied directory, on the branch itself (attached), with `.cloop/` excluded from its commits |
| Wire | `branch_chunk` frames (≤ 512 KiB each), protocol **v16**, written before the start frame on the same connection; the device checks size and digest before building anything |
| Returned | a write-back bundle onto the same branch (`Spec.WriteBack`, mode `bundle`), plus the project result |
| Landed by | `featurehub.Land`: `pkg/writeback.Vet` into quarantine, then a fast-forward of the hub's worktree — only when it is clean, on its branch, the work builds on its HEAD and touches nothing under `.cloop/` — else the work is kept on `cloop/returned/<slug>/<run>` and the feature records a conflict |
| Capability | `supports_branch_bundle`; placement requirement `RequireBranchBundle` |
| Cap | `executors.feature_bundle_mb` (default 32, at most 128), applied by the hub when shipping, by the sandbox when bundling its work, and by the hub again when landing it |

**Per driver.**

| Driver | Feature workloads |
| --- | --- |
| `container` | Stages a standalone checkout in a directory of its own (never the hub's worktree) and mounts it at `/workspace`, with an output directory at `/cloop-out`. The harness runs inside `cloop workspace writeback --place-seed …`, so the seed is placed, the run's state is read back and its work is committed and bundled *inside the container*; the host only reads two files out of `/cloop-out`, as bytes, refusing links, FIFOs and anything over the cap. The sandbox runs as the *parent* project's owner. Staging is removed when the hub has collected the result, or an hour after the workload ended. |
| `remote` (incl. virtual executors) | Protocol v16 and git on the device. An overlay is cloned with the project's grant like any `git` workspace; the agent commits and bundles after the harness exits, in an environment that switches off whatever the workload configured in the tree (`gitprovision.SandboxedRepoEnv`). |
| `kubernetes` | Not supported: a Pod has no channel from the hub to receive the bundle through — the lease Secret that carries its project state holds 1 MiB — and its log cannot carry a bundle back. Refused at dispatch. |
| `localprocess` | Not involved: on a hub that runs projects itself a feature runs in its worktree, as before. |

**The hub runs git for this.** Only something that can read the hub's
filesystem can bundle a feature's branch or land work onto it, and by
construction that is never the executor the feature runs on. So the hub runs git
— and only git, with fixed subcommands, in its own project repositories —
through `pkg/executor/featurehub`, which is part of the executor boundary the
[call-graph guarantee](../security/model.md#the-no-host-execution-guarantee)
sanctions. Every invocation has no system or global configuration and carries
`executor.HardenedGitConfig`: hooks, fsmonitor, every configured filter driver,
signing and automatic maintenance are off, so a hook or filter left in the
repository by a project's own container sandbox (which mounts the project,
`.git` included) never runs on the hub. Creating, removing and publishing a
feature of such a project go through it too (`featureops` in *hub mode*), with
the API token taken only from the project's grant or, on a hub without sign-in,
the hub's own.

**A write-back through a real agent.** Building this found that no real agent
had ever completed a write-back dispatch: after provisioning, the agent handed
its inner driver a Spec that still asked for a write-back on what was now a
`bind` workspace, which `Spec.Validate` refuses. The agent now strips the
write-back before the inner driver sees it — the agent performs it itself, after
the harness exits — and `TestLoopbackReturnsAFeatureRunsCommits` covers the
round trip over a real session.

---

## Secret file delivery

A secret lease produces three shapes of material, and only two of them used to
reach every backend.

| Shape | Carried in | Reaches |
| --- | --- | --- |
| Environment variables | `Spec.Env` | every backend |
| Host paths to bind | `Spec.HostMounts` | backends with `SupportsHostMounts` |
| **Files** | **`Spec.SecretFiles`** | backends with `supports_secret_files` |

The third row is new. Before it, the hub wrote every lease's files into its own
`/dev/shm/cloop-lease-<hex>` and put the resulting paths into the workload's
environment — a delivery only for a workload running on the hub's filesystem.
The container driver forwarded `Spec.Env` and never mounted the directory; the
Kubernetes driver had no consumer for it; the remote protocol had no frame that
could carry a byte of it. Nothing failed. The sandbox started, the harness ran,
and the credential was absent.

It mattered most for the credential that is hardest to scope. GitHub cannot
narrow an already-issued PAT, so "this token may only touch `acme/*`" is
enforced at the moment git asks for it: the grant delivers a credential helper
that stays silent for every other repository, the token it reads, and a
gitconfig installed through `GIT_CONFIG_GLOBAL`. All three are files, and a
narrow grant deliberately exports **no** bare `GITHUB_TOKEN` — an environment
variable is unscoped by construction, so exporting one would hand every tool in
the sandbox a token good for every repository. A sandbox that lost the files
therefore received no credential at all, and failed to authenticate several
minutes later with an error naming none of this.

### Who materialises

Two capabilities, because they answer different questions:

- `SupportsSecretFiles` — do the files reach the workload at all? `false`
  refuses placement with the `secret_files` constraint.
- `SecretFilesFromHostPath` — does the workload read them off the *control
  plane's* filesystem?

Only `localprocess` says yes to the second, and that is the rule: **the hub
writes plaintext only for a backend that will genuinely read it from there.**
Anywhere else it would create a credential file on the control plane that
nothing ever opens. For every isolating backend the lease is rendered in memory
(`Lease.Deliver`, not `Lease.Materialize`) and the bytes travel on
`Spec.SecretFiles`, which is `json:"-"` — so they are absent from the Spec that
`pkg/executorstore` persists, from the audit trail that echoes it, and from the
reconcile loop that re-reads it after a restart.

| Driver | `supports_secret_files` | `SecretFilesFromHostPath` | How the files arrive |
| --- | --- | --- | --- |
| `localprocess` | ✅ | ✅ | the hub's tmpfs directory, opened directly |
| `container` | ✅ | ❌ | staged into a private per-run tmpfs owned by the sandbox UID, bind-mounted read-only at the spec'd directory |
| `kubernetes` | ✅ | ❌ | the per-run `cloop-lease-<handle>` Secret, projected read-only, created right after the Pod — which owns it — and deleted with the workload |
| `remote` | ✅ *if* the device speaks protocol ≥ 6 | ❌ | a `secret_files` field on the start frame; the agent writes them into a `cloop-lease-*` directory of its own |

The container driver is the interesting row: it reports `SharesHostFilesystem`
`true` and still cannot use a hub path, because it has a mount namespace of its
own *and* runs as an unprivileged UID taken from the project directory's owner,
while the hub's lease directory is `0700` owned by the control-plane user. Two
independent reasons, either one sufficient.

### The environment, on Kubernetes

The first row of the table above reaches every backend, and on Kubernetes it
used to reach the Pod object as well: `Spec.Env` was rendered as plain `value:`
entries, readable by every identity with `get pods` in the namespace. That is
where a lease puts what it delivers as environment — an `env` grant's keys,
including the harness login (`CLAUDE_CODE_OAUTH_TOKEN` or `ANTHROPIC_API_KEY`,
the only way a Pod gets one), `GITHUB_TOKEN`/`GH_TOKEN` for a grant over every
repository, an egress grant's proxy URLs and the egress session's
`http://<id>:<token>@host:port` in all four proxy variables.

Since Task 20401 every value travels in the lease Secret beside the files, under
`env.<NAME>` — file keys are `d<N>.<name>`, so the two cannot collide — and the
harness container names each with its own `valueFrom.secretKeyRef`, explicitly
not optional. It is every value rather than only those `CLOOP_REDACT_ENV`
declares sensitive, because a list is one forgotten declaration from a leak and
a constraint like `CLOOP_GITHUB_REPO_ALLOWLIST` loses nothing by moving. The
exception is `GIT_CONFIG_COUNT`, which the driver rewrites to number its own
entries — the workspace's `safe.directory`, the git proxy's CA — after the
Spec's; those and the count are the only plain values left. Not `envFrom`,
either: it imports every key of a Secret, and would put the credential files'
contents into the environment of every process the harness starts. The
workspace provisioner reads none of it, as before. One derivation decides both
the Secret's keys and the Pod's references (`leaseenv.go`), so a reference to a
key the Secret does not carry cannot be built.

A run that leases nothing and sets no environment still creates no Secret, and
so needs no Secret RBAC — `cloop executor test` is one.

**The Secret must exist when the harness is created**, not when the Pod is: a
`secretKeyRef` is resolved by the kubelet at container creation, which behind a
workspace fetch is minutes after the Pod. Two rules follow.

- A hub that stops following a live run (`Close`) deletes a per-run Secret only
  once every container that reads it has started — the provisioner for the
  workspace credential, the harness for the lease Secret (and for the workspace
  credential under a push write-back). Before that it leaves it, with its lease,
  to be reaped with the Pod. It used to delete the lease Secret unconditionally,
  so a hub that restarted mid-fetch stranded the harness.
- A container the kubelet cannot create — reason `CreateContainerConfigError`,
  which the kubelet retries for as long as the Pod exists — fails the run with
  an error naming the missing Secret, and the Pod is deleted even under
  `keep_completed_pods`, since it would otherwise start, unfollowed, the moment
  the Secret reappeared. The Pod is created before its Secrets (they name it as
  their owner), so a kubelet fast enough to try the container in that gap
  reports the same error for an instant; within 45 seconds of the start the
  error is presumed to be that race and looked at again once, after which it is
  final. A run adopted after a restart started long before, so a stranded
  harness found then fails on the first look.

Revocation does not change: deleting the lease Secret cannot take a value back
out of a running process, so env-borne material is kill-only on this backend
exactly as it was — see [revocation per backend](../security/model.md#revocation-per-backend).

### Paths, and who may choose them

The directory in `Spec.SecretFiles[].Dir` is where the *workload* expects the
files, because the broker has already baked it into `GIT_CONFIG_GLOBAL`,
`KUBECONFIG` and `CLOOP_LEASE_DIR`. A driver that can honour it verbatim does:
the container binds at it, Kubernetes mounts at it.

The remote agent does not, and the difference is a threat-model boundary rather
than a convenience. The hub has no idea what is writable on an edge device, and
in this system's model the control plane is a party that can be compromised — so
honouring an absolute path from a frame would hand a compromised hub a
file-write primitive on every enrolled machine. The agent picks its own
directory under a tmpfs, names it with the `cloop-lease-` prefix its own
confinement rule recognises, and calls `Spec.RelocateSecrets` to move `Spec.Env`
and `Spec.Secrets[].Dir`/`.Files` onto it. That last step is load-bearing:
`vault.bind` indexes those paths for revocation, and a revoke naming a path the
agent never wrote is a revoke that reports success having deleted nothing.

### Modes, and read-only

Files are created with the mode the grant asked for — `0600` for a token,
`0700` for the credential helper git has to execute — and never with a group or
other bit. Kubernetes is the one exception in form only: the projected volume
asks for `0400` because the Pod sets `fsGroup` and the kubelet ORs group-read
into a volume it owns, so `0400` lands as an effective `0440`. Asking for `0600`
there would name a mode the kubelet does not preserve.

Every mount is read-only. That is not decoration: a credential helper the
workload could rewrite is a credential helper that answers for every
repository, which would undo the only enforcement point a repository-scoped PAT
has.

### Replacing a file under a running workload

One file changes while its workload runs: a GitHub App installation token,
which GitHub honours for an hour and the hub re-mints before then (Task 20375).
A driver that can rewrite a lease's files in place implements
`executor.SecretRefresher`; the lease keepalive hands it the new file and the
driver puts it where the workload already reads it:

| Driver | Where the file is | How it is replaced |
| --- | --- | --- |
| `localprocess` | the hub's own lease directory | a new file beside it, renamed over it (`executor.ReplaceSecretFile`) |
| `container` | the per-run staging directory, bind-mounted into the container | the same rename, in the staging directory, owned by the sandbox user |
| `remote` | the agent's own lease directory (and, in container mode, bind-mounted into the container) | a `secret_refresh` frame (protocol v17); the agent renames the new file in, keeping the old one's owner |
| `kubernetes` | the run's `cloop-lease-<handle>` Secret, projected as a directory volume with no `subPath` | a JSON merge patch of the one key; the kubelet syncs the volume within its period, so the report says the delivery is eventual |

Every lease directory is mounted **whole**, never file by file, and that is what
makes the rename visible: a bind mount of a directory follows a new entry
renamed into it, where a bind of the file itself would go on showing the inode it
was given. Each driver rewrites only a file the lease already delivered to that
workload — a name it was not given is refused, so a refresh is never a way to
plant a file — refuses a path that is not a regular file inside a lease
directory, and adds the new content to the workload's output redaction before
the rename, since the workload can print it the moment it can read it. A driver
that adopted a workload after a hub restart holds no staging record for it and
reports that, rather than guessing a path.

---

## Supervision, health and failover

`pkg/executor/supervisor.go` runs the probe loop; `pkg/executor/health.go` holds
the state machine. The split matters: `ObserveProbe` is a pure fold of
(current health, probe result) → (new health, transition), so every timing rule
below is unit-testable without waiting for wall-clock time.

```
      probe ok                probe fails             probe fails
        │                    (DegradeAfter=1)       (UnreachableAfter=3)
        ▼                          ▼                       ▼
    ┌────────┐                ┌──────────┐           ┌──────────────┐
    │ ready  │ ─────────────▶ │ degraded │ ────────▶ │ unreachable  │
    └────────┘ ◀───────────── └──────────┘ ◀──────── └──────────────┘
        │  probe ok                                    │ in-flight work
        │                                              │ fails over
        │ operator                                     ▼
        ▼
   ┌──────────┐   drain    ┌──────────┐
   │ cordoned │ ─────────▶ │ draining │      uncordon → the state probes justify,
   └──────────┘            └──────────┘      not optimistically ready
```

| State | New work? | In-flight work? |
| --- | --- | --- |
| `ready` | yes | continues |
| `degraded` | yes, but ranked below ready | continues |
| `unreachable` | no | **failed over** |
| `cordoned` | no | continues untouched |
| `draining` | no | continues; the node is being retired |

Probes run every 30 s with ±20 % jitter, at most 8 concurrently, each bounded by
`ProbeTimeout`. A failing node backs off `5s × 2^(failures-1)`, capped at 5 min.
Probe results can move a node *into* an administrative state but never *out* of
one — only an operator's `uncordon` does that, and it lands the node in whatever
state the probes justify rather than assuming ready.

Operator commands: `cloop executor cordon|drain|uncordon|ls`. `drain` plus
`WaitForDrain` blocks until in-flight work reaches zero or the deadline expires,
returning the remaining count.

### Failover (Task 20162)

When a node transitions to `unreachable`, in-flight sessions move rather than
die. The tricky part is doing it exactly once: two supervisors, or one
supervisor racing its own retry, must not dispatch the same task twice.

```
transition → unreachable
  └─ SessionStore.RunningSessions(deadExecutorID)
       └─ for each session:
            ClaimRequeue(sessionID, claimToken, maxAttempts, now)   ← one atomic UPDATE … WHERE claim_token = ?
              │  token mismatch → ErrSessionClaimLost → return quietly (the guard worked)
              │  attempt > maxAttempts → state failover_exhausted: no placement, no re-dispatch
              └─ otherwise state requeued → placeReplacement: Select(pool minus dead node
                   │                          and restricted executors, …)
                   │  no candidate → FailoverEvent.Err
                   └─ FailoverHandler settles the session's tasks (every claim), then
                      ├─ placed, no task quarantined → the run starts again as the
                      │                                project's run (see below)
                      └─ otherwise, or the replacement refused → the project is paused
                                                                executor_lost
                        └─ EventSink.ExecutorFailover(ev)  → executor.failover or
                                                             executor.failover_exhausted
```

The exactly-once latch is the **claim token**, rotated on every requeue. A
`Session` persists `ID`, `ExecutorID`, `HandleID`, `ProjectPath`, `TaskID`,
`ClaimToken`, `Attempt`, the tasks its run last announced (`RunningTasks`), and
the `Spec` it was dispatched with, leased values redacted. A replacement takes
the command and the project from it, and nothing else: it is dispatched afresh
for the executor it lands on (see [below](#the-replacement-is-the-projects-run-task-20396)).
`ErrSessionClaimLost` is deliberately not logged: it is the normal outcome of a
race, and logging it would train operators to ignore the log.

Sessions live in `executor_sessions`; health in `executor_health` (migrations
`0013`, `0014`), so both survive a hub restart.

### The failover cap and the node-killer quarantine (Task 20391)

A workload that takes its own node down — a fork bomb, one that exhausts
memory, one that panics the kernel — kills the replacement too. Without a
ceiling, failover carried it to every enrolled device in turn.
`executors.failover.max_attempts` bounds that: how many times one dispatch may
be started again elsewhere. Unset it is 2; 0 turns re-dispatch off; the most it
may be is 10. It is a hub-scope key, read from the hub's configuration with its
per-instance overlay at every claim, so lowering it takes effect at the next
failover.

The cap is applied **inside the claim**: the same conditional `UPDATE` that
rotates the token sets the session to `requeued` when its attempt is at most the
cap and to `failover_exhausted` past it. Whoever wins the claim also fixes the
session's fate, so two supervisors — or two hub members whose overlays set
different caps — cannot each decide differently, and a crash between deciding
and recording is impossible. `redispatchSession` refuses any session the store
does not hold as `requeued`, or one already replaced, whatever the event it was
handed says (it can arrive from another hub member).

The failover handler then settles the tasks the lost node was running — on
every claim, placed or not:

| Outcome | Its tasks |
| --- | --- |
| requeued (re-dispatched, or no candidate) | back to `pending`, fail count raised, for the next run |
| `failover_exhausted` | **failed**, the reason naming every node the run was lost on and when it went unreachable |
| the task's losses name 2+ distinct executors | **failed and quarantined** as a suspected node killer, and the run is not re-dispatched (Task 20396) |

Which tasks those are has two sources. A run on an executor sharing the hub's
filesystem writes the hub's plan, so its `in_progress` tasks are the answer. A
run on a device works on a copy, so the session watcher follows the run's own
announcements — the orchestrator's `━━━ Task 7/12: …` lines and their outcome
lines — and records them on the session as `running_tasks`
(`pkg/ui/run_progress.go`). A task the hub's plan already shows finished is
never charged.

Every loss is recorded against the task in the project's `task_node_losses`.
A failed task gets its verdict sidecar first (source `failover`), so stale-run
recovery fails it again rather than resurrecting it; then, for a node killer,
its row in `task_quarantine`; then its status. Each write is what makes losing
the next one safe: a mark that landed without its status leaves a task that
reads pending but is held, never a failed task without a mark. The project journal gets a
`failover` row for each task and for an exhausted run; the hub's trail gets
`executor.failover_exhausted` with every lost node, and the project's gets
`task.quarantine`.

A quarantined task runs again only after an **explicit reset** — `cloop task
reset`, `cloop task bulk reset`, a reset to pending from the dashboard, or
`PATCH /tasks/{id}` on `cloop serve` — which deletes the mark and the losses
behind it and is audited as `task.quarantine_release`. `--retry-failed` skips
it, and the orchestrator's gate holds it even if something else set it pending.
The mark is not a `plan_tasks` column: no save writes or erases it, so a run
holding a copy of the plan from before the mark cannot undo it, and a device
cannot release it — or mark another task — through the result it sends back.
It travels to a device in the seed, so the device's orchestrator holds it too.

`cloop executor list --inventory` lists every quarantined task in the projects
a failover has touched, with the nodes it went down under and the command that
releases it.

### The replacement is the project's run (Task 20396)

Before this, a replacement was started from the stored spec and watched only for
its session to close. The stored spec carries neither the run's leased
credentials nor its project seed, so on an isolating executor the replacement
started with no Claude login and no plan; nothing streamed its output, merged
its result or settled the project; and the hub went on following the stranded
run, whose driver answers "unknown" for as long as the device is away — so its
project showed "running" for as long as the hub lived.

`failover_runs.go` makes the replacement a run like any other:

- **Dispatched as a run.** `startReplacement` calls `startWorkloadAs` with
  `asReplacementFor(target, session)`: the dispatch is pinned to the executor
  placement chose, under the same host-execution policy `Resolve` applies to a
  binding, and its session is recorded as the next attempt of the stranded one's
  chain — which is what the cap counts. Everything else is the ordinary
  dispatch: the harness-credential preflight (acting, like the automatic
  resume, for whoever started the run), a fresh lease checked against the grants
  as they stand, a fresh project seed of the plan the failover just settled, the
  sandbox, firewall levels, egress session, workspace and ceilings composed for
  the replacement, the revocation guarantee, and a placement record naming the
  replacement — so its orchestrator stamps it on the tasks and `task.dispatch`
  rows it writes. Only a `cloop run` is re-dispatched; a session row asking for
  anything else is refused, since it is read back from a database. A project
  the hub no longer serves is not brought back.
- **Followed as a run.** `followReplacement` swaps the replacement in for the
  stranded run in one critical section — the project is never without a run in
  between, which the watcher would read as a death — takes the run's owner row,
  writes a line into the live log saying where the run went, and follows it as
  `handleRun` does: the live log on every dashboard, `consumeRunOutput`, and
  `runEnded` when it ends, which merges a seeded run's result and settles the
  project. The journal records "Run failed over from executor X to Y".
- **The stranded run given up.** Its egress session and leases close — a
  workload out of reach keeps no credential, and with the lease go its git-proxy
  and Kubernetes-monitor sessions — and its driver is told to give it up. A
  driver that implements `executor.Abandoner` (the remote one) marks the handle
  terminal, which closes its stream and lets every watcher go, forgets its
  durable row, and answers the device's resume offer for it with "terminate"
  when it comes back. Any other driver is asked to kill it. Its consumer is
  marked handed over, so a stream that ends after all does not settle the
  project under its replacement.
- **A loss nothing replaced.** With no candidate, past the cap, with a task
  quarantined, or when the replacement is refused (no harness credential, a
  sandbox the executor cannot honour), the stranded run is given up and the
  project settled at once — paused with an `executor_lost` reason naming the
  executor and the cause — and the journal records "Executor X was lost and the
  run was not re-dispatched: …". Starting it again is an ordinary dispatch to
  the project's binding. A project that is running again by then — a person
  pressed Run while the failover was under way — gets no replacement and no
  pause: another run is executing it.
- **The session store is authoritative.** `projectExecuting` asks it about a
  followed run whose driver calls it alive or cannot answer: a session the claim
  recorded as replaced, `failover_exhausted`, or requeued long enough ago that
  no replacement is coming is not executing; a requeued one with no replacement
  yet counts as executing for `failoverReplacementWindow` (5 minutes), so nobody
  starts a second run beside one about to begin. With no verdict an unreachable
  driver still fails closed.
- **Restricted executors, and the hub's own host.** An executor with an access
  list is checked against the claims of the person starting a run, and a
  failover starts it on nobody's behalf. Placement passes over every restricted
  executor (`WithCandidateFilter`), and the dispatch path refuses one routed to
  it anyway. And a run that was isolated from the hub — on a device, a
  container, a VM — is never failed over onto the hub's own host, whatever
  `allow_host_process` says (`requirementsFor`): the host driver, with no
  concurrency limit, would otherwise outrank every device on free slots.

On a hub cluster (Task 20354) the parts happen where they can. The supervisor
that claims a session runs on the member probing the executor — the leader, for
an agent no member holds. A replacement on an edge agent is started by the
member holding the agent's socket (`agentOpRedispatch`), which follows it and
takes the run's owner row from the member that followed the stranded run. That
member is told so on the bus (`run_lost`) and retires the stranded run; if the
message is lost, its watcher finds the claim in the session store within ten
seconds (`sweepLostRuns`) — and a run whose owner died is never adopted once a
failover has claimed it. A loss nothing replaced is settled by the member that
followed the stranded run, told the same way.

---

## End to end

```mermaid
flowchart TB
    subgraph browser["Browser"]
        UI["Dashboard"]
    end

    subgraph hub["cloop hub — never forks a harness"]
        direction TB
        RT["routes.go: gate(routeSpec)<br/>RBAC — deny by default"]
        ORCH["pkg/orchestrator<br/>runPM: next task"]
        SW["ui/executor.go<br/>startWorkload / runWorkload"]
        REG["Registry.Resolve(projectPath)<br/>binding → persistent → default"]
        POL{"policy.go<br/>HostExecutionAllowed?"}
        SB["secretbroker.Lease<br/>+ egressbroker session"]
        SUP["Supervisor<br/>probe · cordon · failover"]
        SESS[("executor_sessions<br/>executor_health")]
    end

    subgraph backends["Executor backends"]
        LP["localprocess<br/>isolation: none"]
        CT["container<br/>isolation: container / vm"]
        RM["remote<br/>isolation: remote"]
        K8["kubernetes<br/>isolation: remote"]
    end

    subgraph sandboxes["Where work actually runs"]
        PROC["child process<br/>(host)"]
        DOCK["Docker/Podman<br/>--read-only --cap-drop=ALL<br/>--network=none<br/>--runtime kata → own kernel"]
        EDGE["edge device<br/>agent dials OUT"]
        POD["ephemeral Pod<br/>runAsNonRoot, RO rootfs"]
    end

    UI -->|"HTTPS + session cookie"| RT
    RT --> ORCH
    ORCH -->|"Spec: Argv, WorkDir, Labels"| SW
    SW --> REG
    REG --> POL
    POL -->|"denied → HostExecutionDeniedError<br/>(+ isolated alternatives)"| RT
    POL -->|allowed| SB
    SB -->|"lease → Spec.Env + files (tmpfs)"| DISPATCH["ex.Start(ctx, spec) → Handle"]
    DISPATCH --> LP & CT & RM & K8
    LP --> PROC
    CT --> DOCK
    RM -.->|"WebSocket, agent-initiated"| EDGE
    K8 -->|"Pod create + log follow"| POD

    PROC & DOCK & EDGE & POD -.->|"LogLine + Status"| STREAM["ex.Stream → logbus<br/>replay 64 KiB, gaps visible"]
    STREAM --> WS["WebSocket → dashboard"]
    WS --> UI

    DISPATCH --> SESS
    SUP -->|"HealthCheck every 30s ±20%"| LP & CT & RM & K8
    SUP -->|"unreachable → ClaimRequeue"| SESS
    SESS -->|"re-place on surviving node"| DISPATCH

    %% Tints, not opaque fills, and no text colour: see
    %% tests/docs/diagram_contrast_test.go.
    style POL fill:#cc339926,stroke:#c39
    style SB fill:#5f8f2f26,stroke:#5f8f2f
    style hub fill:#8888881a,stroke:#888
```

The call chain in code, for the common "start a run" path
(`pkg/ui/executor.go:216`):

```
startWorkload(workDir, argv, labels)
  registerBuiltinExecutors()
  executor.Resolve(workDir)              → Executor  |  *HostExecutionDeniedError
  acquireSecretLease(cpDir, workDir, id) → *secretLease        (pkg/ui/secrets.go:90)
  applyLease(uiSpec(...), lease)          → Spec with env + tmpfs file paths
  ex.Start(context.Background(), spec)    → Handle             (detached on purpose)
  openSessionFor(cpDir, ex, handle, spec) → session row        (makes failover possible)
  wipeLeaseOnExit(ex, handle, lease)      → waits for terminal state, then zeroes the lease dir
```

`runWorkload` (`executor.go:292`) is the synchronous sibling used for short
commands: it calls `executor.Run`, which ties workload lifetime to the caller's
context and collects combined output with a 4 MiB tail-heavy cap.

## Startup reconciliation

At boot, `bootstrapExecutors(dir)` runs in a fixed order that is itself a
safety property:

1. **apply the host-execution policy** — first, because registering before
   applying it would leave a window in which a host executor is schedulable;
2. **register the built-in host driver** — before the configured ones, so it
   stays the registry default on a permissive single-machine install. Under
   strict mode this registration is refused and the first isolating driver
   becomes the default instead;
3. **reconcile the configured drivers** — `reconcile.Bootstrap(dir, cfg, opts)`;
4. install the persistent binding lookup, sync the registry to the store, and
   only then start the supervisor.

Step 3 is `pkg/executor/reconcile`, and all three hosting entry points go
through it: `cloop ui`, `cloop serve`, and every CLI command via
`cmd/root.go`'s `PersistentPreRunE`. It cannot live in `pkg/executor` itself —
`pkg/config` imports the container and Kubernetes driver packages for their
`Options` types, so a `pkg/executor` that imported `pkg/config` would close an
import cycle.

Reconciliation reads `executors.container.*` and `executors.kubernetes.*`,
builds each enabled driver, runs its preflight, and records a **diagnostic**
per driver: `id`, `kind`, `status`, `registered`, `message`, `remediation`, and
the preflight checklist. Three statuses matter:

| Status | Registered? | Meaning |
| --- | --- | --- |
| `ok` | yes | built and preflight found nothing fatal |
| `degraded` | yes | built, but preflight found a fatal problem |
| `failed` | no | could not be built at all — no container runtime on PATH, no kubeconfig grant |

`degraded` staying registered is deliberate. Preflight is a point-in-time probe
of a remote system; a driver dropped because the cluster was restarting during
boot would stay gone until someone restarted the hub, which is worse than one
that reports the problem and lets the next dispatch retry.

`Bootstrap` registers synchronously and preflights in the background, because
the two halves have opposite latency budgets: registration must finish before
the listener opens (or `/readyz` would report a hub with no executors as ready
purely because bootstrap had not got there yet), while preflight is a runtime
round-trip that would make `cloop ui` look hung on a host with a wedged docker
daemon. Running both is safe because reconciliation is **idempotent** — a
driver already in the registry is reused rather than rebuilt, which matters
beyond tidiness for the Kubernetes driver, whose credential source opens a
state database it holds for the process's lifetime.

Diagnostics are surfaced in three places, so a failure cannot be silent:

- **startup logs**, one line per driver plus the remediation;
- **`GET /api/executors`**, as a `reconciliation` block and as per-card
  `reconcile_status` / `reconcile_remediation` fields. A `failed` driver has no
  registry entry and no `executors` row, so this is the *only* place it
  appears;
- **`/readyz`**, which reports `not_ready` with `"check": "executors"` when
  strict mode is on and no isolating executor is registered. That verdict is
  computed live rather than frozen at startup, so a hub becomes ready the
  moment an edge device enrolls.

### Durable handle identity (Task 20191)

Reconciliation above brings the *drivers* back. The workloads they dispatched
are a separate problem, and until Task 20191 they were not solved at all.

Every driver keeps its handle map in memory. That is the right place for the
live bookkeeping — a log bus, a kill timer, a cancel func — but it also made
the map the only record that a workload existed. A control plane that restarted
came up believing it had dispatched nothing, while the containers, Pods and
edge-device processes it had dispatched kept running. `Stream`, `Status` and
`Signal` all answered `ErrHandleNotFound` for them, so the workload was
simultaneously alive and unreachable: no output, no status, no way to stop it.

The fix splits identity from liveness. A `HandleRecord` carries only what is
needed to *find* a workload again, and that survives the process; the live
bookkeeping is rebuilt from it on the next start ("rehydration"). This works
because the runtime, not cloop, owns the workload: `docker logs -f` and a Pod
log follow attach to something nobody in this process started just as happily
as to something it did.

Identity lives in `executor_handles` (migration `0021`):

| Column | Meaning |
| --- | --- |
| `handle_id` | the driver-side handle, and the key callers hold |
| `executor_id` | owning executor instance; rehydration is scoped by it, so two container executors on one runtime cannot adopt each other's containers |
| `driver` | the `Kind*` constant, so a sweep can reason about rows whose executor is no longer registered at all |
| `external_id` | the name the *runtime* knows the workload by — the whole point of the row |
| `project_path`, `task_id` | what the work was, so an operator reading the table can tell, and a sweep can scope itself to one project |
| `pid` | the OS pid where one is meaningful (`localprocess`), else 0 |
| `image` | the resolved image reference that actually ran — the digest the tag pointed to at dispatch, not the configured tag, which may have been repointed since. Empty for drivers with no image |
| `meta_json` | driver-specific extras, stored verbatim, never secrets |
| `secrets_json` | the workload's secret-lease bindings (migration `0031`) — lease ids, variable *names*, paths; never values. Three states, and the last two are not the same: `''` unrecorded, `'[]'` recorded-and-none, `'[…]'` the bindings. See below |
| `started_at` | dispatch time, not row-write time, because the orphan sweep ages against it |
| `deadline` | the instant `Spec.TimeoutMinutes` expires, or empty for an unbounded workload. Absolute rather than a duration, so a restart resumes the remaining time instead of restarting the clock |
| `updated_at` | last write, for operator forensics |

`external_id` is driver-specific and nothing outside the owning driver
interprets it:

| Driver | `external_id` |
| --- | --- |
| `localprocess` | the OS process ID, in decimal |
| `container` | the container name |
| `kubernetes` | `namespace/podname` |
| `remote` | the agent-side handle ID (the same string as `handle_id`; the agent offers it back on reconnect) |

**This is deliberately not `executor_sessions` (`0013`)**, even though the two
describe overlapping things. `executor_sessions` is the *control plane's*
ledger: the supervisor opens a row when it dispatches, failover requeues from
it, drain counts it, its key is a session ID the control plane minted, and it
retains the `Spec` so a session can be re-dispatched somewhere else.
`executor_handles` is the *driver's* ledger: the driver writes a row when the
runtime accepts a workload and drops it when the workload goes terminal, keyed
by the driver-side handle and carrying the external name. Collapsing them would
mean either drivers minting claim tokens they have no business minting, or the
control plane inventing external IDs it cannot know — and it would break the
case that motivated the split, since a driver used without the supervisor (the
CLI, an embedder) still needs to survive a restart and never gets a session row.

**There is no `spec_json` column, on purpose.** `Spec.Env` carries brokered
secret values, and a handle row outlives the lease those values came from.
Rehydration reattaches to a *running* workload and never re-dispatches one, so
it needs no `Spec`; `executor_sessions` keeps one where re-dispatch actually
happens. Widening the blast radius of a stolen state database to duplicate it
here would buy nothing.

**`secrets_json` is the one part of the `Spec` that does get stored**, and the
distinction is a property of the type rather than an exception to the rule
above. Identity alone turned out to be too little: a rehydrated handle could be
streamed, signalled and reaped, but the driver's lease→handle index stayed in
memory, so a workload that survived a restart answered `HoldsLease` with false
and a revocation aimed at it reported nothing-to-revoke — a success code for a
credential still in use. `SecretBinding` holds lease ids, environment variable
*names*, file paths and a TTL and no values, which is the same property that
already lets the control plane write bindings into `executor_sessions` and into
audit rows.

A row that predates the column cannot say what its workload holds, and `''` is
therefore **not** read as "held nothing": the adopting driver marks the handle
*unresolved*, `HoldsLease` answers true so the executor is still asked, and the
revocation reports a failure naming the handle instead of a success. The mark
clears when the workload exits. See [What it is worth after a hub
restart](../security/model.md#what-it-is-worth-after-a-hub-restart).

The one part of the `Spec` that had to survive anyway is the timeout, and it
does — as a `deadline` column of its own rather than as a persisted `Spec`.
It is stored as an **absolute instant, not a duration**, and the two disagree
in exactly the case it exists for: a hub down for twenty minutes must resume a
one-hour timeout with forty minutes left, not restart the hour. A duration
would silently extend every timeout by the length of the outage.

Re-arming is a correctness requirement rather than a nicety. An adopted
workload is *tracked*, so no orphan sweep will ever collect it; without the
deadline, a task with a one-hour cap that outlived a restart would run until
the host was rebooted — trading the bug this section describes for a quieter
version of it. A deadline that has already passed arms at zero and kills on the
next tick: the timeout expired, and nobody having been there to enforce it is
not a reprieve.

Only the drivers holding a `time.AfterFunc` in the hub's own process
(`localprocess`, `container`) write a deadline. The Kubernetes driver leaves it
zero, because it hands the API server `activeDeadlineSeconds`, which already
survives a control-plane restart — which is why a client-side timer was the
wrong mechanism there in the first place. A zero deadline arms no timer, so a
workload that was deliberately uncapped stays uncapped.

There is also no foreign key to `executors`, for the same reason
`executor_health` has none — in-process drivers never enroll, and they are
exactly the drivers whose orphans an operator most often has to clean up.

Persistence is **best-effort in both directions**. `RecordHandle`,
`ForgetHandle` and `LoadHandles` report failure to stderr and never propagate
it. A workload that started successfully must not be reported as failed because
the state database was momentarily locked: the caller would mark the task failed
and retry it, producing the double execution the whole scheduling layer exists
to prevent. A lost row degrades to exactly the pre-Task-20191 behaviour, which
is the floor rather than a new failure. A driver that cannot *read* its rows
still constructs, for the same reason: a hub that refuses to start over a stale
row leaves the operator with no hub at all.

Where the row is written differs by driver, and the asymmetry is the point.
`container` and `kubernetes` write it *after* the runtime has accepted the
workload and after the map insert, because a row written earlier would name
nothing, and a crash in between only loses a row for a container that is running
— which the orphan sweep already handles. `remote` writes it *before* the start
frame goes out, because the workload comes into existence on another machine on
the far side of a link that may be an LTE modem, and the whole round trip is a
window in which this process can die while the device is already running the
harness; `dropHandle` deletes the row on every failure path, and after a restart
an adopted handle the device never started is resolved by the first heartbeat
that does not list it.

The store is resolved once per reconciliation pass and threaded into both
configured drivers, so the two never open separate handles onto the same
database. `reconcile.Options.HandleStore` overrides it, `DisableHandleStore`
opts out entirely (tests reconciling into a temp directory, which should not
create a state database as a side effect), and drivers registered *outside*
reconciliation — the `localprocess` singleton, a remote executor whose device
dialled in — receive it through `AttachHandleStore`, matched structurally rather
than by a type switch so a driver added later cannot be silently skipped.

### What each driver can and cannot recover

| | `container` | `kubernetes` | `remote` | `localprocess` |
| --- | --- | --- | --- | --- |
| Status / liveness | yes | yes | yes, once the agent reconnects | yes, from `/proc` |
| Output stream | yes, re-read from the start | yes, re-read from the start | whatever the device still retains | **no** |
| Exit code | yes | yes | yes | **no** |
| Signal / stop | yes | yes | yes | yes, after re-verifying identity |
| Timeout | yes, re-armed from `deadline` | yes, the API server enforces it | yes, the agent's own timer never stopped | yes, re-armed from `deadline` |

**`container`.** Adoption is a map insert, a fresh log bus and a pump; every
runtime call happens on the pump's goroutine, so `New` keeps its promise of no
I/O. The record starts `Running`, which is a claim rather than an observation,
and the pump corrects it within milliseconds — a live container streams until it
exits, an already-exited one yields its backlog and recorded exit code, and one
that is gone entirely fails `wait`, which finishes the handle and *drops the
row*. That last case is what stops a stale row being re-adopted and re-failed on
every boot forever. `meta_json` records the runtime that started the container,
because podman and docker keep entirely separate container stores: a hub
reconfigured between restarts is reattaching against a namespace where its
containers do not exist, and the one legible warning it prints is the only hint
an operator gets that a live sandbox has been left behind under a runtime
nothing is watching.

**`kubernetes`.** `adopt` inserts into the handle map *synchronously*, before
`New` returns and before anything can call `ReconcileOrphans` — a tracked Pod is
never swept, and that ordering is what keeps the sweep safe to run on a hub
whose workloads are still going. Only then does the adopted handle's own
goroutine do cluster I/O. Three things cannot come out of a row and each is
handled by saying so rather than pretending: the **kubeconfig lease** is
re-acquired through the same `Options.Credentials` path `Start` uses, with the
same project ID, so a grant revoked while the hub was down is not silently
resumed on authority that no longer exists (failure to lease finishes the record
and hands the Pod to the orphan sweep); the **`Spec`**, so an adopted record does
not know a write-back was *asked for* and a run that produces no report reads as
"no write-back" rather than "a failed one"; and the **workspace provisioning
state**, which by restart time has either already done its job or is still
needed by a Pending Pod. The log is re-read from the beginning rather than
tailed, so the reattached stream is the whole run.

What the row *does* carry beyond identity is the one piece of cleanup state no
API query can reconstruct: the name of the egress NetworkPolicy created
alongside the Pod. The policy selects the Pod by label, so the Pod does not name
it back, and a rehydrated handle that had forgotten it would leave a firewall
object behind for the orphan sweep to find minutes later. `project_path` is
likewise the same string the original dispatch leased its kubeconfig with rather
than the Pod's project annotation, because a value that resolved to a different
grant would hand the reattached handle authority over a namespace this run was
never entitled to.

**`remote`.** Almost nothing has to be rebuilt — the device holds the process,
its output buffer and its exit code, and this side holds a name, a bus and a
status — so adoption is a map insert with no I/O, which is why it runs
synchronously inside `NewExecutor`: it must finish before the hub's listener can
accept the agent whose resume offer it exists to match. What a row cannot carry
is the log offset. Adding a durable counter would put a database write in the
path of every 32 KiB of output, so an adopted handle starts at offset 0 and asks
the device for everything it still has; the device's retain buffer is capped
(1 MiB, `agent.DefaultRetainBytes`) so the replay is bounded, and the handle is
flagged **gapped** regardless — a workload that produced output before the
restart and none after resends nothing at all, and between "this log may be
missing its start" and "here is the whole run", only the first is safe to be
wrong about.

**`localprocess` recovers least, and says so.** A forked child is not killed
when its parent dies: the kernel reparents it to init and it carries on holding
the CPU, the network and the project directory. What survives is only what the
kernel tracks independently of parentage.

- **Stream is not recoverable.** The child's stdout and stderr were an
  `os.Pipe` whose read end died with the previous process; the write end the
  child still holds now goes nowhere, and there is no way to re-open it. The
  adopted handle emits one `[cloop]` line saying exactly that, through the same
  path real output takes, so it lands in the replay buffer for every subscriber
  that attaches later.
- **Exit status is not recoverable.** `wait4` reports only to a parent. An
  adopted workload that exits is finished as `failed` with exit code `-1` and an
  error naming the reason, never as `exited(0)` — a caller reads the exit code
  to decide whether a task succeeded, and guessing zero there would mark failed
  work as done.
- **A bare pid is never treated as identity.** A pid is a small recycled
  integer: between the old control plane dying and the new one adopting the row,
  the child may have exited and its number been handed to a database, an ssh
  session, or the operator's shell. Acting on that would deliver SIGKILL to an
  unrelated process. Identity is instead a pair recorded at dispatch and
  compared exactly at adoption — `/proc/<pid>/stat` field 22 (start time in
  clock ticks, assigned at fork and never changed) and
  `/proc/sys/kernel/random/boot_id`, which closes the hole that tick counts
  restart from zero after a reboot. Anything that cannot be checked against that
  pair is treated as gone: the handle is finished as failed and its row deleted.
  The check is re-run immediately before **every** signal, not only at adoption,
  because the window reopens continuously.
- Liveness is polled once a second, because the exit of a process that is not
  our child produces no event to wait for — `wait4` answers only for our own
  children and SIGCHLD is never delivered for one init inherited. The netlink
  proc connector needs `CAP_NET_ADMIN` (so a hub running as an ordinary user
  would lose rehydration entirely rather than degrade) and `pidfd_open(2)`, the
  right primitive, needs a dependency change; the poll is the honest interim.

### The restart sweep

Rehydration lives in the drivers, because only a driver knows how to re-open
`docker logs -f`. `reconcile.Sweep` owns the three things left over afterwards,
none of which any single driver can see. It is requested by
`reconcile.Options.ReconcileOrphans`, which was Kubernetes-only before Task 20191
and is now the full sweep; the entry points that ask for it are the ones a
control plane actually restarts as (`cloop ui`, `cloop serve`, and `daemon`,
`run` and `agent` through `cmd/root.go`), because for a short CLI call it is
only latency and API traffic.

```
FromConfig
  ├─ reconcileContainer  → driver constructed → rehydrate()   ← adopt, synchronously
  │                      → go sweepContainerOrphans           ← only on the pass that registered it
  ├─ reconcileKubernetes → driver constructed → rehydrate()
  │                      → go sweepOrphans
  ├─ attachHandleStores  → the localprocess singleton, enrolled remote executors
  ├─ publish the report
  ├─ go Sweep(dir)
  │    ├─ sweepSessions   → close stale `running` rows; return the task IDs that survived
  │    └─ pruneWorktrees  → collect leaked worktrees, sparing those task IDs
  └─ StartPeriodicSweep   → and again every 15m, for the orphans a restart never sees
```

### The periodic sweep

Startup-only answered "what did the process I am replacing leave behind?", and
that is not the only way to orphan a workload. A node eviction, a cluster
upgrade that drains a node, or an operator deleting a Pod all strand an object
while the hub is perfectly healthy — and before Task 20281 those accumulated
until someone restarted it, which is the one operation a healthy deployment
never performs.

`reconcile.StartPeriodicSweep` re-runs the same per-driver reapers every
`executors.orphan_sweep_interval_minutes` (default 15, `0` disables). It is the
identical code path, deliberately, so there is no second implementation to
drift; repeating it is safe by construction, because a tracked workload is never
touched and an untracked one is only removed once it is past the grace period.

Exactly one sweeper runs per process — `StartPeriodicSweep` replaces rather than
adds, since `Bootstrap` reconciles twice by design — and both hub binaries stop
it from `Shutdown`. The last pass is published through `reconcile.LastSweep` and
surfaced on `GET /api/executors` as `sweep`, with the per-driver breakdown: a
driver whose sweep is *failing* is the condition an operator has to act on,
because a Role that lost its `list` rule leaves a namespace quietly filling with
Pods and nothing else in the UI would ever say why.

The ordering is not incidental. Rehydration must have happened first, because
the question the session sweep asks — "does this row's executor still own its
handle?" — is only answerable once the drivers have adopted what they own, and
because a Pod or container that has been adopted is in the tracked set before
the orphan sweep goroutine is spawned. Sessions are settled before worktrees,
because the set of task IDs still legitimately running is exactly the set of
sessions that survived; pruning first would delete the worktree of a task that
is still being worked on, which is unrecoverable.

The whole sweep is detached and bounded at two minutes, and every step is
independently recoverable. A git prune and a runtime listing must not sit
between a hub's start and its listener, and a hub whose state database is
momentarily locked must still come up — it just comes up with the mess still
there and sweeps it on the next restart. Nothing in here is fatal and nothing is
half-done: closed rows stay closed, reaped containers stay reaped, a pruned
worktree is gone.

**Stale sessions.** `openSessionFor` writes a `running` row that only an
in-memory goroutine closes, and a hub that dies takes that goroutine with it.
Nothing else ever touched those rows: `RunningSessions` is called from exactly
one place, inside `failOver`, reachable only from a live healthy→unreachable
transition — and a restarted hub sees its local and container executors as
healthy, so no transition fires. `WaitForDrain` polls until the in-flight count
reaches zero, so a single stale row made `cloop executor drain` and the UI drain
button fail with `ErrDrainTimeout` permanently on any executor that had a run in
flight during the restart. Every `running` row now gets a verdict:

| Situation | Verdict |
| --- | --- |
| executor registered, reports a live handle | left alone; its task ID is returned so the worktree sweep spares it |
| executor registered, does not know the handle | closed with the terminal state the driver reports, or `failed` when it reports nothing |
| executor not registered, but the hub holds an edge-device handle for the workload | left alone: enrolled agents register after this sweep runs, and the process the device reconnects to adopts the run and watches the session to its end ([below](#the-project-comes-back-task-20339)) |
| executor not registered at all | closed as `failed` — the executor was removed, and we genuinely do not know how the work ended |
| session never obtained a handle | closed as `failed`: `Start` failed, or the hub died inside it |

`sessionOutcome` biases towards **live**, and the bias is the safe direction: a
driver that cannot answer — `Status` returned something that is not
`ErrHandleNotFound`, a cluster that is unreachable right now — is treated as
still running. Closing a session whose workload is actually alive would let the
scheduler re-place its task, producing two agents editing one repository.
Leaving it open costs a drain that waits, and the next restart re-evaluates it.

**Leaked worktrees.** `pkg/worktree` cleaned only the same task path on the next
`Create`, and `Remove` deliberately left the branch, so a parallel run killed
between `git worktree add` and its merge leaked both the directory and the
`cloop/task-N-*` branch permanently — and nothing ever looked at
`.cloop/worktrees` as a whole. `worktree.List` now reconciles two sources, `git
worktree list --porcelain` and the directory itself, because the interesting
cases are exactly where they disagree: a directory with no registration is what
a `git worktree prune` leaves, a registration with no directory is what an
`rm -rf` leaves, and a sweep looking at only one source is blind to one of them.
Only entries under `<repo>/.cloop/worktrees` are ever returned, which is what
keeps the operator's own checkout out of a sweep's reach even if it happens to
have a `cloop/task-N` branch checked out.

Two guards make it safe to run unattended, and they are not interchangeable.
`MinAge` (default 2 h) is the backstop that holds even when the caller's idea of
what is running is wrong or missing — a directory's mtime does not move when an
agent rewrites a file three levels down, so it can only ever be a heuristic. The
surviving sessions, passed as `Active`, are the precise answer: a task that has
been running for six hours is older than any sane `MinAge` and is exactly the
one whose worktree must not be touched. A `git worktree lock` is honoured
unconditionally, and a directory whose age cannot be read at all is kept.

**Branches are never deleted by the sweep.** `worktree.Prune` can delete merged
ones, but an unattended sweep would have to be certain what "merged" means for a
repository it did not configure, and the cost of being wrong is destroyed work
against a saved-disk-space figure of nearly zero. `cloop worktree prune
--delete-branches` is where an operator asks for it deliberately, and even there
the check is enforced twice — an explicit `for-each-ref --merged` query and then
`git branch -d` rather than `-D`, which is never used anywhere in the package —
so an error in the first still cannot destroy unmerged work. Squash-merged
branches are kept, because no ancestry test can see a squash and a stale ref is
cheaper than somebody's work.

### Orphan grace periods

Reaping is what happens when rehydration could not save the run. An executor
with a handle store adopts its own workloads at construction and therefore
tracks them, so the sweep only ever sees what a process with no durable store,
or one whose rows were lost, left behind.

Before Task 20191, `container.ReapOrphans` filtered `status=exited` only and was
called from nothing but the manual `cloop executor reap` CLI. A hub killed
mid-run therefore left a **running** sandbox container burning CPU indefinitely,
with nobody reading its output and no reaper anywhere. Both backends now collect
two populations, and they are deliberately not symmetric:

- **Terminated workloads are removed immediately.** An exited container holds a
  name and a writable layer and nothing else, so the worst case of removing a
  peer's is that peer losing a `docker logs` it had not read.
- **Running workloads are removed only after `OrphanGracePeriod`** (10 minutes
  by default for both drivers). For a container, all of these must hold: it
  carries `cloop.managed=true`, it carries this executor's own `cloop.executor`
  id (two container executors on one host must not reap each other's work), it
  carries a `cloop.handle` label at all (a hand-made container wearing the
  managed label is not ours to kill), this executor does not track it, and the
  *runtime* says it has been running longer than the grace period.

The grace period is a correctness condition rather than a courtesy. `ps` returns
a snapshot, and between that snapshot and the tracked-name check a container can
legitimately be both running and untracked: our own `start()` has had `run -d`
return but has not yet reached the map insert, or a second control plane sharing
the runtime is inside the same window. Both are microseconds to milliseconds
wide; anything older has a demonstrably absent owner. Ten minutes is far wider
than the race it guards, which is the correct direction to be wrong in — an
orphan reaped ten minutes late costs CPU, one reaped ten milliseconds early
costs somebody's run.

Every uncertain input resolves to "do not touch": a zero grace period (which is
what an un-normalised `Options` carries, so honouring it would make the
least-configured executor the most destructive), a container whose timestamp
cannot be parsed, and one that claims to have started in the future, which means
the runtime's clock and ours disagree. The comparison uses the *runtime's* start
time, never the local clock at listing time — that records when we looked, which
is the same instant for a container that started an hour ago and one that
started while the `ps` was in flight, precisely the two cases the check has to
tell apart.

A running container is collected with `rm --force`, which is SIGKILL plus
removal in one call. The Kubernetes driver offers a termination grace period
because a Pod's results live inside it; a sandbox container's workspace is a
bind mount whose writes are already on the host's disk, and this container has
by definition been running unobserved for longer than the grace period.

Configured as
[`executors.container.orphan_grace_period_seconds`](../reference/configuration.md#container-sandbox)
and `executors.kubernetes.orphan_grace_period_seconds`.

### Resume or terminate: protocol v5

The remote driver's failure was the worst of the four, because its reconnect
protocol made it permanent. The agent offers its surviving handles in the hello;
`reconcileResume` answered from the (empty) handle map and refused every one;
the agent read the refusal as "stop reporting" and dropped its bookkeeping
**without stopping the process**. The result was a harness running forever on an
edge device — output discarded, invisible to the UI, unstoppable, with no reaper
on either side. Nothing about it looked wrong from the control plane: the run had
simply vanished.

Rehydration makes the offer matchable again. The other half is that a refusal
now has to mean something, so `ProtocolVersion` went 4 → 5:

```go
type ResumeAck struct {
    HandleID   string
    FromOffset int64        // meaningless when Action is terminate
    Action     ResumeAction // "continue" | "terminate"; empty means continue
    Reason     string       // carried into the device's own log
}
```

Absence used to be the only way to say no, and absence cannot be distinguished
from an old hub, a truncated list, or a bug — so the agent's only safe reading of
it was the destructive one. Naming the verdict makes the destructive path
deliberate and lets it carry a reason the device can write in its own log, which
is where an operator looks when a workload dies moments after the hub came back.
`ResumeAck.Effective()` defaults an absent *or unrecognised* action to
`continue`, for the same reason `RevokePayload.Effective` defaults to scrub: an
agent meeting a control plane speaking a dialect it does not understand must
fail towards keeping the work, because the workload is hours of compute and the
ack is one field.

**Backward compatibility runs in both directions, and they are not symmetric.**

`MinResumeTerminateVersion` is 5, but unlike `MinRevocationVersion`,
`MinWorkspaceVersion` and `MinWriteBackVersion` it is **not a placement rule** —
there is nothing to refuse to place. It governs what the hub may *say* to an
agent that is already connected and already running work. An older agent does
not reject an unknown `Action`, it ignores it, and then reads the handle's mere
presence in `ResumeAccepted` as permission to keep streaming — which for a
handle the hub has forgotten means chunks answered with `unknown_handle`
forever. So the hub omits refusals entirely below v5, reproducing the pre-v5
wire byte for byte: the agent sees the handle missing and abandons it, which is
what it did before. That is the floor this change must not go below.

The leak is therefore closed on the **device** side. An upgraded agent's
`applyResume` stops a disowned workload whatever the hub's version, treating
both shapes of refusal the same way — an explicit `terminate`, and *no entry at
all*, which is the only refusal a pre-v5 hub can express and is still what one
sends. Since agents are upgraded independently of hubs, and most of a fleet is
un-upgraded for most of a rollout, the fix has to reach it through the half that
can actually stop a process. Stopping is ordered before forgetting, because the
terminate needs the workload still in the map to find its process, and `forget`
runs on every path — including the one where there was nothing to signal,
because for a workload still fetching its source tree `forget` is what cancels
the fetch.

One bound: `maxResumeRefusals` (256) caps how many terminate verdicts one
welcome may carry. Acceptances are bounded by what this hub dispatched, but a
refusal is emitted for anything the peer cares to list, so an unbounded list
would let a device offering a megabyte of invented handle IDs push the welcome
past `MaxFrameBytes` — an amplification costing the hub the work and the agent
its session. Offers past the cap fall through to omission, which an upgraded
agent still reads as "stop this", so the bound costs nothing but the reason text.

A hub configured with no handle store is still supported and behaves exactly as
it did before Task 20191, with one changed consequence worth stating: every
resume offer is refused, and a refusal now stops the workload. A storeless hub
trades a leaked process for a lost run.

---

## Remote agent enrollment

The inversion that makes edge devices practical: the hub never dials the device.
The device dials the hub, so it works behind NAT, behind a corporate firewall,
on a residential connection, with no inbound port and no static address.

```mermaid
sequenceDiagram
    participant Op as Operator
    participant Hub as cloop hub
    participant Dev as Edge device

    Op->>Hub: cloop executor enroll --name edge-1 --ttl 15m
    Note over Hub: mint 32-byte secret<br/>store SHA-256 only<br/>token = clet1.<id>.<secret>.<HMAC>
    Hub-->>Op: enrollment bundle (--server, --token, --pin)

    Op->>Dev: cloop executor agent --bundle <bundle>
    Dev->>Hub: WSS /api/executors/connect + Bearer token
    Note over Dev: verify hub cert against<br/>pinned SPKI (sha256:…)
    Note over Hub: verify HMAC, then constant-time<br/>compare SHA-256, then<br/>UPDATE … WHERE redeemed_at IS NULL
    Hub-->>Dev: long-lived credential (clac1…) + Welcome
    Note over Dev: persist 0600 at ~/.cloop/agent.json

    loop while enrolled
        Dev->>Hub: heartbeat (15s ±25%)
        Hub->>Dev: Start / Signal / Status / Stream frames
        Dev-->>Hub: LogLine chunks (resumable by byte offset)
    end

    Op->>Hub: cloop executor revoke <id>
    Hub-->>Dev: bye (reconnect=false)
```

Enrollment tokens are **single-use and time-bounded**: default TTL 15 min,
maximum 24 h, redeemed by an atomic `UPDATE … WHERE redeemed_at IS NULL` so that
two devices racing the same token cannot both end up with the identity
(`remote/enroll.go:273-336`). The token carries a truncated HMAC so a malformed
or tampered token is rejected by shape before it ever reaches the database. Only
SHA-256 hashes of the secret and of the subsequent credential are stored, so a
dump of the control plane's database does not yield a usable credential.

The agent reconnects with exponential backoff (1 s → 2 min, ±25 % jitter) and
never gives up on its own; only operator cancellation or a hub-side revocation
(`bye` with `reconnect=false`) ends the loop. Workloads confined beneath
`--workdir-root` survive reconnects.

**Paths do not cross the wire.** The hub's `Spec.WorkDir` is a directory on the
*hub*; an agent confines every workload beneath its own root and refuses an
absolute path from outside it, treating a workload's path as attacker-controlled
input from a control plane that might be compromised. So the caller that builds
the spec rewrites it — `executor.DeviceWorkDir` turns
`/var/lib/cloop/projects/api` into `api-9aef699b`, derived from the full path so
that two projects sharing a base name cannot collide on one device, and stable
across runs so the device keeps its clone instead of re-fetching every time. The
rewrite is on the hub side, next to the `SharesHostFilesystem` test that makes
the same judgement, and not in the driver: a driver that quietly remapped an
absolute path would also remap one a compromised hub aimed at `/etc`, turning
the agent's refusal into a silent redirect.

**Automated enrollment.** `cloop executor enroll --bundle-file <path>` writes the
bundle to a 0600 file instead of leaving it only in the printed command, for the
case where the same automation mints the token and starts the device — a compose
one-shot, cloud-init, an Ansible play. The agent reads it with `--token-file` and
deletes it once redeemed. `docker-compose.yml` does exactly this, and
`make e2e-stack` runs the result end to end: the hub comes up with nothing to
dispatch to and `/readyz` is red, the executor enrolls itself and it goes green,
then a real task runs on the device against a tree it fetched over HTTPS. See
[deploy/README.md](../../deploy/README.md).

Transport is covered in [the security model](../security/model.md#②-hub--remote-agent).

**Confirming a device actually works.** An agent that has connected shows as
`ready` in the Executors panel, which means its heartbeat arrives — not that it
can run anything. The difference is where the time goes when a fleet
misbehaves: a device whose harness image has no shell, whose workspace root is
not writable, or whose protocol is too old to accept a credential heartbeats
perfectly and fails every task.

```console
$ cloop hub doctor --smoke --executor edge-1
```

That dispatches a hermetic workload — no network, no repository, no model call
— through placement, workspace provisioning, a throwaway credential lease, log
streaming, teardown and write-back, and reports each leg separately. It leaves
nothing behind on the device or the hub, and its exit code distinguishes a
broken executor (4) from a misconfigured hub (1). Run it once per device after
enrolling, and on a timer against the whole fleet; see
[the runbook](../operations/runbook.md#dispatch-health-cloop-hub-doctor---smoke).

Two failures it catches that nothing else does, both specific to edge devices:

- **An expired or replayed enrollment token.** Both now carry a remediation
  rather than a bare error. They are not the same problem: an expired token
  means mint another and mind the `--ttl`, while a replayed one may mean
  somebody redeemed it before the device did — in which case revoking the agent
  it created matters more than enrolling again.
- **A harness image with an `ENTRYPOINT`.** The container driver will not
  override one (that would change what argv means), so the arguments are
  appended to it and something else runs. A harness image must leave
  `ENTRYPOINT` empty and let cloop supply argv.

### Installing the agent as a service

`cloop executor agent --bundle …` runs in the foreground and installs nothing.
For a device you intend to keep, `cloop executor agent install` materialises the
whole deployment instead:

```bash
# On the device, as root. The bundle rides in the environment, not in argv.
CLOOP_ENROLL_BUNDLE='cloopenroll1.…' sudo -E cloop executor agent install

# Or fetch the bootstrap script from the hub (HTTPS only — see below).
CLOOP_ENROLL_BUNDLE='cloopenroll1.…' sh -c "$(curl -fsSL https://hub.example.com/install.sh)"
```

It writes three files and nothing else:

| Path | Mode | Contents |
| --- | --- | --- |
| `/etc/systemd/system/cloop-executor.service` | `0644` | the unit — **no credential** |
| `/etc/systemd/system/cloop-executor.service.d/10-packet-filter.conf` | `0644` | the one relaxation: `CAP_NET_ADMIN` and `AF_NETLINK`, so the agent can install a sandbox's firewall (not written with `--packet-filter=false`) |
| `/var/lib/cloop-executor/enrollment` | `0600` | the enrollment bundle, owned by the service user |

The split is the point. A unit file is world-readable and `systemctl show`
prints `ExecStart` to any local user, so the token reaches the agent as a *path*
(`--token-file`) rather than as an argument. The agent deletes that file once
the token has been redeemed, after the long-lived credential is safely on disk —
a single-use secret should not survive into every later backup of the device.

The generated unit runs as a dedicated non-login system user with
`Restart=always`, `NoNewPrivileges=yes`, `ProtectSystem=strict`, `ProtectHome`,
`PrivateTmp`, `PrivateDevices`, `ProtectProc=invisible`, an empty
`CapabilityBoundingSet`, `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`,
`SystemCallFilter=@system-service` and `UMask=0077`, with the hub's SPKI pin
baked into `ExecStart`. `StateDirectory=` gives it exactly one writable
directory. A device that runs *container* workloads through the agent must drop
`PrivateDevices=` and `RestrictNamespaces=`; the unit says so in a comment where
the operator will find it.

The packet-filter drop-in is the installer's only relaxation, and it is a
separate file so the unit is byte-identical with or without it, an upgrade can
add or remove it without the enrollment bundle, and an operator can delete the
whole grant as one file. Its three directives *add* to the unit's — systemd
merges them — so the effective bounding and ambient sets are exactly
`CAP_NET_ADMIN`, and `AF_NETLINK` joins `AF_INET AF_INET6 AF_UNIX`. Because an
ambient capability is inherited by every program a process starts, every cloop
process first clears its ambient and inheritable sets on all threads
(`pkg/caps`: `AllThreadsSyscall` in a `CGO_ENABLED=0` build, a C constructor
that runs before the Go runtime's first thread in a cgo build), and
`pkg/netfilter` hands the capability back only to `nft(8)`. The agent holds
`CAP_NET_ADMIN`; nothing it starts does. See
[Virtual executors](../guides/virtual-executors.md#what-the-device-needs).

Other outputs and flags:

| Flag | Effect |
| --- | --- |
| `--output docker` | a `podman run` command and a compose fragment with the equivalent confinement (`--cap-drop ALL`, `--read-only`, `--security-opt no-new-privileges`); the credential is a read-only bind mount, never `-e` |
| `--output shell` | a POSIX init script with a supervision loop, for devices with no systemd |
| `--dry-run` | prints the unit and the file list; writes nothing |
| `--uninstall` | reverses the install; idempotent, and verifies afterwards that no unit or credential survives |
| `--purge` | with `--uninstall`, also removes the agent's identity and workspaces |
| `--root <dir>` | stages the files for a golden image instead of installing them |
| `--no-start` | installs and enables without starting, for first-boot enrollment |
| `--upgrade` | replaces the binary of an existing install and restarts it — see [Upgrading a device](#upgrading-a-device) |
| `--from <path>` | with `--upgrade`, the new binary (default: the running executable) |
| `--force` | with `--upgrade`, replace and restart even when the installed binary is already identical |
| `--packet-filter` | on by default: writes the drop-in granting `CAP_NET_ADMIN` and `AF_NETLINK`; `=false` withholds it and removes a drop-in an earlier install left. With `--upgrade` it acts only when passed — `--upgrade --packet-filter` grants it on a device installed without it, restarting the agent even if its build is current; a plain `--upgrade` never changes it |

**`GET /install.sh`** serves the bootstrap script. It is gated on
`executor.manage` — the same permission as minting a token, since it discloses
the hub's URL and pin — and it **refuses to answer over plaintext HTTP** with a
`403`, no loopback exemption and no redirect. Its body is piped into a root
shell on a device that has not yet decided whom to trust, so anyone able to
rewrite it in flight owns the device. The URL and pin are rendered from the
request (honouring `X-Forwarded-Proto` / `X-Forwarded-Host` from loopback and
`ui.trusted_proxies` only — Task 20394), because a hosted
hub's configured name is frequently not the one the operator reached. The script
carries no credential: it locates a `cloop` binary and hands off to
`cloop executor agent install`, where the hardening above actually lives.

It prefers a binary the device already has — `CLOOP_BIN`, then `cloop` on
`PATH`, then `/usr/local/bin/cloop`, then `/usr/bin/cloop` — so an operator who
pinned or built a version does not have it replaced behind their back. Only when
there is none does it download
`https://github.com/blechschmidt/cloop/releases/latest/download/cloop_<os>_<arch>.tar.gz`
(override the base with `CLOOP_RELEASES`), verify it against the release's
`checksums.txt`, and install it to `/usr/local/bin/cloop` at mode `0755`.

That verification fails closed: a mismatch, an unreachable `checksums.txt`, or
an artifact missing from it all abort the install rather than proceed
unverified. The archive is unpacked as root onto a machine that is about to be
handed credentials, so TLS authenticating the transport is not on its own
enough. An operator who wants to skip the download entirely already has
`CLOOP_BIN`.

The asset name carries no version, because `latest/download` resolves only a
fixed name — see [Installation](../getting-started/installation.md).

### Fleet inventory: which build is each device running?

Every agent reports its own build version and a hardware advertisement in its
`hello` frame. The hub records both on the device's executor row — refreshed on
**every connect**, not at enrollment — so the fleet can be inventoried from the
control plane without touching a device.

Refreshing on connect rather than at enrollment is the whole design. Enrollment
happens once in a device's life; an upgrade is precisely the event that changes
these facts. Recording them at enrollment would freeze each device's reported
build at its join date, so an upgraded device would go on being reported as the
build it arrived with.

| Column | From | Used for |
| --- | --- | --- |
| `agent_version` | `HelloPayload.AgentVersion` | version-skew detection |
| `agent_os`, `agent_arch` | `AgentCapabilities` | placement, "which arm64 devices trail" |
| `agent_cpus`, `agent_memory_mb` | `AgentCapabilities` | capacity, `MinMemoryMB` placement |
| `agent_harnesses` | `AgentCapabilities` | `Requirements.Harnesses` placement |
| `agent_runtimes` | `AgentCapabilities` | `RequireContainerRuntime` placement |
| `agent_workdir_root` | `AgentCapabilities` | the sandbox boundary, for isolation audits |

`capabilities_json` still holds the *full* advertisement alongside these. The
columns are a projection of the fields that have to be selectable and typed; the
blob is the forward-compatible copy, so a capability a newer agent advertises is
preserved even before it has a column of its own.

Read it from the Executors panel, or:

```bash
cloop executor agents              # BUILD column; "!" marks material skew
cloop executor agents --inventory  # hardware and installed harnesses per device
```

**Skew classification** lives in `pkg/version` and compares an agent's build
against the hub's. Only a *material* skew is surfaced as a warning — patch drift
across a fleet is normal, and a warning on every card would train operators to
ignore the one that matters.

| Class | Meaning | Material |
| --- | --- | --- |
| `none` | same build as the hub | no |
| `patch` | trails by a patch release | no |
| `behind` | trails by a minor or major release | **yes** |
| `ahead` | newer than the hub — it can speak frames the hub does not implement | **yes** |
| `legacy` | reported the placeholder that pre-inventory agents sent | **yes** |
| `unknown` | reported no version at all | no |
| `unversioned` | one side is an unstamped `dev` build, so the two cannot be ordered | **yes** |

`legacy` is recognised explicitly rather than compared, because it is actively
misleading: agents built before build-version reporting sent a hardcoded `1`,
and parsed as a version that is major 1 — which sorts *above* the hub's `v0.x`.
A naive comparison would report the devices most in need of upgrading as being
ahead of their control plane.

A build version only exists if the linker put one there. Release builds are
stamped with
`-ldflags "-X github.com/blechschmidt/cloop/pkg/version.Version=v1.2.3"`; a
`go build` with no stamp reports `dev` plus the short commit
(`dev+g4f7b5bc`, or `dev+g4f7b5bc.dirty` for an uncommitted tree), which is why
an unstamped agent is classified `unversioned` rather than silently assumed
current.

### Installing a missing harness

A device reports the agent CLIs it has (`claude`, `codex`, `gemini`, `cloop`) in
its hello, and the hub refuses a host-mode dispatch whose harness is not among
them. That refusal replaced a much worse failure — the run used to start, lease a
GitHub credential, provision a workspace, and only then die on
`exec: "claude": executable file not found in $PATH` — but for the case that
produces it most often, a device enrolled ten minutes ago, the right answer is
not a better error. It is to install the thing.

So the hub tries first. When a host-mode dispatch needs a harness the device
lacks, it sends an `install_harness` frame (protocol v12); the device installs,
reports the outcome, and the same dispatch carries on. Only if that cannot help
does the refusal appear — now carrying the device's own account of why.

**The hub names a harness, not a script.** This is the protocol's second remote
code execution primitive, and it is constrained exactly like the first:

| The frame carries      | The frame must never carry                     |
| ---------------------- | ---------------------------------------------- |
| a harness name, a reason | a URL, a script, an argv, an env, an interpreter |

The device holds the name→installer table, compiled in, and today it has one
entry: `claude` → `https://claude.ai/install.sh`. A hub that has been taken over
can ask for Claude Code from Anthropic and for nothing else.
`TestInstallHarnessPayloadHasNoRemoteCodeExecutionFields` enforces the right-hand
column by reflection, so a later field that widens it fails the build rather than
quietly enlarging the blast radius of a hub compromise.

The agent fetches the script itself instead of shelling out to `curl … | bash`.
That is what lets it check the *final* URL after redirects — a CDN compromise
that redirects elsewhere is refused rather than piped into a shell — bound the
body, run without inheriting the agent's own environment (its enrollment
credential is in there), and capture the output so a failure reaches the hub.

**Unlike upgrade, the answer is a real outcome.** An upgrade restarts the agent
and destroys the session its reply would travel on, so the best it can report is
"accepted". Installing a harness restarts nothing, so the device reports whether
the binary is now there — which is what makes install-then-continue possible
inside one dispatch.

**PATH is half the feature.** The official installer needs no root and writes no
system path: `claude` lands in `~/.local/bin`, which is not on a systemd unit's
`PATH`. Without a fix for that the device would install the harness, fail to
detect it, refuse the dispatch it was trying to unblock, and install it again
next time. The agent therefore adds its per-user harness directories to its own
environment — which detection and any inheriting payload then see — *and* to any
payload `Spec` carrying an explicit `PATH`, because `cmd.Env` replaces rather
than adds and a leased credential always produces an explicit environment. Fix
only the first and the harness resolves for projects without a secret grant and
not for projects with one, which is not a distinction anyone would test by hand.

Operators who do not want a vendor script run on their machines set
[`executors.auto_install_harness: false`](../reference/configuration.md#automatic-harness-installation)
and get the plain refusal back.

### Upgrading a device

```bash
# On the device, after copying the new binary onto it.
sudo cloop executor agent install --upgrade

# Or from an explicit path, without replacing the binary you are running.
sudo cloop executor agent install --upgrade --from /tmp/cloop-new

# Or fetch a published build and verify its signature, as the hub's Upgrade
# button does: a release tag, "latest", or on an edge-channel device
# edge:<commit> (Task 20376).
sudo cloop executor agent install --upgrade --to v0.0.4

# See what it would do first. This runs the real checks, including executing
# the new binary — a dry run that only echoed the flags back would not be worth
# running before bouncing a service on a device you cannot easily reach.
cloop executor agent install --upgrade --dry-run
```

`--upgrade` replaces the binary atomically (write beside, `fsync`, rename — a
running executable cannot be opened for writing on Linux at all) and then asks
systemd to `try-restart` the unit. `try-restart` rather than `restart`, so a
service an operator deliberately stopped stays stopped.

It leaves the unit alone, and with it the firewall grant: a plain upgrade never
adds or removes the packet-filter drop-in. Passing `--packet-filter` (or
`--packet-filter=false`) makes it write (or remove) the drop-in as part of the
upgrade — even when the binary is already current, in which case nothing is
copied and the agent is restarted so the grant takes effect — and a service
that does not come back gets the previous drop-in back along with the previous
binary. That is how a device installed before the grant was the default gets
it, with no enrollment bundle:

```bash
sudo cloop executor agent install --upgrade --packet-filter
```

Two more device-side settings travel the same way, as files beside the unit
that an upgrade keeps and only an explicit flag changes (Task 20376):

- `--channel edge` (or `stable`) writes or removes `20-update-channel.conf`,
  which puts the device on the [edge channel](../guides/edge-channel.md): it may
  then be upgraded to the hub's own build, signed by CI, as well as to
  releases. Only root on the device can set it; the hub only reads it, from the
  hello.
- `--remote-upgrade` (or `=false`) installs or removes the root helper that
  carries out an upgrade the hub asks for — see below. `--channel edge` installs
  it too unless told otherwise, and a fresh install has it by default.

#### Upgrades the hub asks for: the remote-upgrade helper

The Executors panel's Upgrade button and the auto-update policy send the device
an upgrade frame naming a version. The agent that receives it runs as an
unprivileged system user with `ProtectSystem=strict` and `NoNewPrivileges` — it
cannot replace `/usr/local/bin/cloop`, which is root's, nor restart its own
unit. Until Task 20376 it ran the installer in-process anyway, so on every
device installed with the defaults the button was accepted and the upgrade then
failed in the device's journal.

So the agent hands the work over:

```mermaid
sequenceDiagram
    participant Hub
    participant Agent as agent (unprivileged)
    participant Path as cloop-executor-upgrade.path
    participant Helper as cloop-executor-upgrade.service (root)
    Hub->>Agent: upgrade {target_version}
    Agent->>Agent: preflight: installed, channel allows the target, helper and cosign present
    Agent-->>Hub: upgrading {accepted}
    Agent->>Path: writes upgrade-request.json in its state directory
    Path->>Helper: start
    Helper->>Helper: take and delete the request, channel from systemctl show
    Helper->>Helper: fetch from the pinned repository, verify with cosign
    Helper->>Agent: install --upgrade: identify, rename, keep cloop.prev, try-restart
    Agent-->>Hub: reconnects reporting the new build
```

The request mirrors the frame — version, force, settle time, reason — and
nothing else, so anything that can write it (the agent, or a workload running as
its user) can ask for exactly what the hub can. The helper takes the device's
channel from systemd's view of the agent's unit, never from the request, and
ignores a request more than 15 minutes old. One code path serves the helper,
an agent that runs as root (which does the work itself), and
`install --upgrade --to`: `agent.UpgradeTo`.

A device that cannot carry an upgrade out — no helper and an agent that is not
root, a helper whose path unit is not active (`systemctl is-active` says so;
an answer that is not a unit state does not refuse), or no `cosign` on its
`PATH` — says so in its hello (`remote_upgrade_issue`) and refuses an upgrade
before acknowledging it. The hub does not refuse on the hello: it is as old as
the session, so the dialog shows it as a warning beside the target, and
pressing Upgrade asks the device, which answers from a preflight it runs then —
an operator who installed cosign after the agent connected is not turned away
until it reconnects. A refusal comes back as `accepted: false` with the
device's reason.

The agent also refuses a settle time over 600 seconds, the most the helper's
unit (`TimeoutStartSec=15min`) leaves room for, rather than acknowledge a
request the helper would drop; the helper refuses one too. The helper's
journal lines quote the request with control characters removed, so a request
cannot forge a line. And `<name>-upgrade` is the helper of the agent called
`<name>`: a fresh install refuses a service name ending in `-upgrade`.

#### The staged binary is executed before it is installed

Comparing checksums answers exactly one question — "are these the same bytes" —
and a truncated download, a binary built for another architecture, and a text
file all pass it. All three used to be renamed over a working agent's binary and
the service restarted, which on an unreachable edge device means a site visit.

So the new binary is run first, with a timeout, in a directory containing no
cloop project, against `cloop version --json`:

```json
{ "version": "v0.1.0", "go": "go1.25.9", "os": "linux", "arch": "amd64",
  "protocol": 6, "min_protocol": 1,
  "commit": "4453c682382a8fbdf49952966fdfd0b205f02d2b", "sequence": 921 }
```

`commit` and `sequence` are the build's place on main (Task 20380): the commit
it was made from and that commit's first-parent position,
`git rev-list --count --first-parent <commit>`, which `scripts/build-release.sh`
stamps into every release and edge build. A build that was not stamped — a
developer's `go build`, and every build before the stamp existed — reports
neither.

A binary older than that flag exits non-zero on it, which is information rather
than failure: the probe falls back to plain `cloop version`, whose first line has
read `cloop <version>` since the command existed, and records the protocol
numbers as unknown rather than inventing them.

The refusals that come out of this divide on whether `--force` can override
them:

| Refusal | `--force`? | Why |
| --- | --- | --- |
| will not execute here (`ENOEXEC`, timeout, non-zero exit) | **no** | a binary that will not run before the rename will not run after it |
| ran, but did not identify itself as cloop | **no** | the likely cause is a path typo pointing at another tool |
| does not report the version, commit and sequence its signed edge manifest names | **no** | these are not the bytes the manifest describes — a validly signed manifest for one commit paired with a binary of another |
| earlier on main than the installed build: a lower sequence, or none while the installed binary has one (`ErrRollback`) | **only a local root `--force`** | the one ordering two builds of main have; the upgrade request the agent files and the frame the hub sends carry a force flag that cannot reach this — see [rollback protection](#rollback-protection) |
| older build than the one installed | yes | a deliberate rollback is a real operation |
| speaks an older executor protocol than the installed binary | yes | it would take away whatever the hub can only ask of the newer protocol — checked whether or not the two builds can be ordered, so a release cannot replace a newer `dev+g…` build unnoticed |
| speaks a protocol below the hub's `MinProtocolVersion` | yes | installing it would take the device out of the fleet — the hub would refuse its hello frame |

`--force` has always meant "replace even though the bytes are identical". It is
deliberately not widened to mean "install something proven broken": that would
delete the only check standing between a bad download and an offline device. The
two downgrade cases are overridable because refusing them outright would send an
operator backing out a bad release to `cp` and `systemctl`, bypassing every other
check here.

An unreleased `dev+g…` build is *allowed* by the version comparison. It cannot be
ordered against a release by version, and a developer testing a fix on a device
is legitimate — the binary has already been shown to run, which is the check that
matters. What it may not do is speak an older protocol than the binary it
replaces, or sit earlier on main: both report their protocol and their sequence,
and neither comparison needs a version order.

#### Rollback protection

Every edge build is genuinely signed, including the thirty-odd older ones the
edge release keeps, and all of them report `dev+g<sha>` — so before Task 20380
the guard above could not order two of them, and the root helper would install
any older signed edge build at the same protocol that an unprivileged agent, or a
compromised hub, asked for: one from before a fix to the agent or to the helper
itself.

The sequence orders them. The installer refuses a staged build whose sequence is
lower than the installed binary's, reading **both from the binaries' own
`version --json`** — never from the request file, the hub's frame or the agent:

- An installed binary with no sequence is the bootstrap case (a build from before
  the stamp, or a hand-made one): allowed, with a journal line saying the device
  enforces the order from then on.
- A staged binary with no sequence over one that has one is refused: every signed
  build since the stamp carries one, so a signed build without one is older.
- When the probe of the installed binary fails and the installer *is* that binary
  — the root helper always is (`ExecStart=<binary> executor agent install
  --upgrade --apply-request`) — the installer reads its own identity instead, so
  a probe a hostile agent could make fail cannot make the installed build look
  sequence-less.

Only `UpgradeOptions.AllowRollback` overrides the refusal, and only the CLI sets
it — from `--force` on an `install --upgrade` (with `--from` or `--to`) run by
root on the device. `--apply-request --force` is refused outright, because the
request names the target. A refusal is logged in the helper's journal
(`journalctl -u <service>-upgrade.service`): `refused: … would move this device
back on main from … (sequence N on main) to … (sequence M on main)`.

#### A failed upgrade is reverted

Execution proves the binary runs *here*. It cannot prove it will stay up
*there* — a newer libc than the device has, a startup panic on its hardware —
and the only evidence of that is a service that will not stay running, by which
point the binary that worked is gone.

So the replaced binary is kept beside the new one at `<binary>.prev` (one
generation, not one per upgrade — a device with a small root filesystem must not
fill up from routine rollouts), and after the restart the upgrade waits up to 30
seconds, `--settle-timeout` to change, for the service to report itself active.
If it does not, the previous binary is restored and restarted, and the command
fails saying the device is still in the fleet.

Whether the service was running is sampled **before** the restart, not after.
`try-restart` succeeds whether or not it restarted anything, so afterwards a
service an operator had deliberately stopped is indistinguishable from one that
crashed on the new build — and rolling back on that would revert a good upgrade
every time it landed on a stopped agent, including every device installed with
`--no-start`.

If the restore itself fails, that is the one outcome needing a human on the
device, and it is reported as such rather than in the same register as an
ordinary failure.

It deliberately does **not** re-render the unit file and does not touch the
credential. The unit embeds the hub URL and the certificate pin, both of which
arrive in an enrollment bundle that an operator upgrading a device months later
does not have in hand; re-rendering from a bare spec would quietly write a unit
pointing at no server, turning "your agent is one version behind" into "your
agent no longer knows where its hub is". Changing the unit means re-running a
full install with the bundle.

Five properties, each covered by a test:

- **Idempotent.** An upgrade to a byte-identical binary copies nothing and
  restarts nothing, and says so. Pass `--force` to replace and restart anyway.
- **Refuses what it cannot do.** On a device that was never installed it fails
  with `ErrNotInstalled` and names the install command, rather than leaving a
  binary with no supervisor around it. With `--output docker` there is no binary
  on the filesystem to replace, so it refuses and prints the pull-and-recreate
  procedure instead.
- **Verified.** The staged binary is executed and made to identify itself before
  anything is replaced.
- **Reversible.** The replaced binary is kept, and restored if a service that
  was running does not come back on the new build.
- **Honest about the outcome.** "Nothing needed doing", "replaced and
  restarted", and "replaced but the service was not running" are three different
  successes, and the last one — where everything looks fine and the old build is
  still what would run — gets a warning. A skipped verification is printed as
  skipped, never omitted: output with no verification line would reasonably read
  as "checked and good".

The one mode where the binary is *not* executed is `--root`, which stages an
install tree for a different machine. That machine's binary may legitimately not
run on this one, which is the same reason `--root` never invokes `systemctl`.

### Moving a device forward: which remedy works

When a device's agent speaks too old a protocol for what the hub is asking of
it, the refusal says three things: the protocol the device speaks, the one the
hub needs and what for, and the remedy. All of them are composed by one helper,
`executor.NeedsProtocol` in `pkg/executor/protocolneed.go`, and
`TestProtocolRefusalsGoThroughTheHelper` fails the build when a "needs vN"
sentence is written anywhere else in `pkg/`, `cmd/` or the dashboard's scripts.

The remedy is chosen by **the hub's own build**, because the two ways to move a
device behave differently:

- The Executors panel's **Upgrade** button and the fleet **auto-update** policy
  can only make a device install a *signed* build: a published release, or —
  on a device whose operator put it on the [edge channel](../guides/edge-channel.md)
  — the hub's own build as CI signed it. The hub names a version; the device
  fetches it through its own pinned repository and verifies the signature
  against the identity of its channel. The hub never supplies bytes — that is
  the security model of the upgrade frame.
- `cloop executor agent install --upgrade`, run on the device, installs whatever
  binary runs it (or `--from`). A binary built from source carries no signed
  provenance, and a release signs its *archive*, not the binary inside, so a
  binary copied over by hand needs `--insecure-skip-verify`. A plain `--upgrade`
  leaves the packet-filter drop-in as it is.

| The hub runs | The refusal tells you to |
| --- | --- |
| a release, e.g. `v0.2.0` | press Upgrade to install that release; a device below protocol v11, which cannot be upgraded remotely, once by hand |
| an unreleased build of a commit, e.g. `dev+g8b418e2` | put the device on the edge channel (`sudo cloop executor agent install --upgrade --channel edge`, once) and press Upgrade: it installs the hub's own build, signed by CI, once CI has published it. Or, without the channel, build cloop at the hub's commit (`CGO_ENABLED=0 go build -o cloop .`), copy it to the device and run `sudo ./cloop executor agent install --upgrade --insecure-skip-verify` there. Where the newest published release *does* satisfy the need, pressing Upgrade with it is offered as well |
| an unreleased build of a dirty tree, or `dev` | the hand-built binary only — no CI build matches it |

For the reference deployment — a hub on `dev+g8b418e2`, a device whose agent
speaks v14, a run carrying firewall rules stored in the hub — the refusal reads:

> agent sgx-1 (sgx) speaks protocol v14, and the hub needs v15 for the firewall
> rules stored in the hub that this run carries, which the agent must install
> and check itself — an older one would ignore them. The hub runs an unreleased
> build (dev+g8b418e2), so no published release may speak v15 yet — the newest
> this hub knows of, v0.0.4, speaks v13 — and the Executors panel's Upgrade
> button and auto-update install published releases, and this hub's own build
> only on a device that follows the edge channel. To move the device forward,
> put the device on the edge channel (`sudo cloop executor agent install
> --upgrade --channel edge` on it, once — a cloop older than the channel first
> needs one edge build installed by hand) and press Upgrade on its row in the
> Executors panel: it installs this hub's own build, 8b418e2, signed by CI, once
> CI has published it. Or build cloop at the hub's commit 8b418e2 as a static
> binary (`CGO_ENABLED=0 go build -o cloop .`), copy it to the device and run
> `sudo ./cloop executor agent install --upgrade --insecure-skip-verify` there
> (a binary built by hand carries no signed provenance); a plain --upgrade keeps
> the device's packet-filter grant as it is.

Pressing Upgrade on that device, where `latest` is v0.0.4, is refused before
anything is sent:

> agent sgx-1 (sgx) speaks protocol v14; v0.0.4 speaks v13, so installing it
> would lower the device's protocol and lose what needs v14. The hub runs an
> unreleased build (dev+g8b418e2), and the Executors panel's Upgrade button and
> auto-update install published releases, and this hub's own build only on a
> device that follows the edge channel. To move the device forward, put the
> device on the edge channel … (as above). Ask with force to install it anyway.

**The Upgrade button never moves a device backwards.** The hub knows which
releases were published and the protocol each speaks (`pkg/version/releases.go`;
add a release's entry in the commit that is tagged), and the panel's version
skew compares protocols as well as builds: a connected device below the hub's
protocol is material skew whatever its build string says. The dialog offers the
hub's own release when the hub is one; on a device that follows the edge
channel, the hub's own build (`edge:<commit>`) once CI has published it and if
its manifest's protocol is not below the device's — saying plainly why not
otherwise: an unpushed commit, CI still running, CI failed (see the
[edge channel guide](../guides/edge-channel.md#upgrading-from-the-dashboard));
otherwise the newest published release that would not lower the device's
protocol — and when there is none, it shows the explanation and the build path
instead of a prompt. Behind it, `POST /api/executors/{id}/upgrade`:

- resolves `latest` (or an empty target) to the tag it names today and asks the
  device for that tag, so what is installed is what was checked; a failed lookup
  keeps `latest` on the wire and judges it as the newest release the hub knows
  of, and says so;
- refuses a target that is not a release tag — the hub's own `dev+g…` version,
  say — with **400**, except on an edge-channel device, where the hub's own
  version means its edge build;
- accepts `edge:<commit>` for a device that follows the edge channel, looks up
  that build's manifest to judge its protocol, and refuses it with **409** for a
  device on the stable channel, for a build CI has not published, and for one
  that would lower the device's protocol unless `force`;
- asks a device that said at hello it cannot carry out an upgrade (no
  remote-upgrade helper for an unprivileged agent, a helper that is not armed,
  or no cosign) anyway: the device's own preflight answers, with
  `accepted: false` and its reason when the cause is still there;
- refuses a release whose binaries speak an older protocol than the device does
  with **409**, unless the request sets `force`; a device too old to be upgraded
  remotely is also a **409**.

The auto-update planner applies the same two refusals before it compares
versions, so a device on a dev build is told the protocol reason rather than
"cannot order". Its default target on an unreleased hub — the hub's own
version — is, for a device on the edge channel, the hub's edge build once CI has
published it and if it does not lower the device's protocol; for any other
device it is refused as no release at all, with the command that would put the
device on the channel. Each verdict carries its own target, since the two
channels converge on different builds. And the device checks once more:
`install --upgrade` refuses a staged binary that speaks an older protocol than
the installed one (see the table above), and one that does not report the
version its signed manifest names.

---

## See also

- [Security model](../security/model.md) — what each boundary authenticates with
- [Threat model](../security/threat-model.md) — STRIDE per boundary
- [Secret and egress grants](../guides/secrets.md) — what a sandbox is given
- [Kata Containers](../guides/kata.md) — installing and verifying a VM sandbox
- [Operator runbook](../operations/runbook.md) — backup, rotation, upgrade
