# Running workloads in a VM (Kata Containers)

This guide shows how to give cloop's sandboxes a kernel of their own, on a
single host and on a cluster, and how to check that it worked.

cloop's default sandbox is a container: namespaces, cgroups, seccomp and dropped
capabilities, all enforced by the kernel the workload runs on. That suits most
deployments. It is a weaker boundary than it looks when the code inside was
written by a model and runs on someone else's behalf: a local privilege
escalation in that kernel compromises the whole machine.

[Kata Containers](https://katacontainers.io) runs each container inside a
lightweight VM. The workload gets its own guest kernel, and the host's kernel
sits behind a hypervisor. A kernel bug is then no longer enough to reach the
host: an attacker also needs a hypervisor escape.

Two configuration keys turn it on, one for each backend. Leaving them empty
changes nothing:

| | Key | Effect |
| --- | --- | --- |
| local | `executors.container.oci_runtime` | podman or docker runs with `--runtime <name>` |
| cluster | `executors.kubernetes.runtime_class` | every workload Pod gets `runtimeClassName` |

Before you decide it solves a problem you have, read
[what this does and does not change](../security/model.md#the-kernel-underneath-the-sandbox).
Egress, the shared workspace mount and the credentials a workload holds are
all unchanged.

- [Prerequisite: the host must be able to start a VM](#prerequisite-the-host-must-be-able-to-start-a-vm)
- [Local: podman or docker](#local-podman-or-docker)
- [Verifying it](#verifying-it)
- [Kubernetes](#kubernetes)
- [Requiring it](#requiring-it)
- [Troubleshooting](#troubleshooting)

---

## Prerequisite: the host must be able to start a VM

Kata needs `/dev/kvm`, and the user cloop runs as must be able to open it
read-write. Both can fail in ways that are easy to miss:

```console
$ ls -l /dev/kvm
crw-rw---- 1 root kvm 10, 232 /dev/kvm
```

That is what a working host shows. The two failures are:

**No `/dev/kvm` at all.** On a hosted deployment, the usual cause is that the
hub is itself a VM with nested virtualization turned off. Nested virtualization
is a property of the instance you rent, and no package can install it:

- **GCP**: the instance needs `--enable-nested-virtualization`, and the licence
  is set on the disk image.
- **AWS**: a `.metal` instance type, or one of the families that exposes
  nested virtualization.
- **Azure**: a size that supports it (`Dv3`/`Ev3` and later).
- **Bare metal**: check that VT-x/AMD-V is enabled in firmware and that
  `kvm_intel` or `kvm_amd` is loaded.

If none of those is available, run Kata on a machine that is not the hub: an
enrolled remote executor, or a Kubernetes node pool.

**Present but not openable.** On most distributions `/dev/kvm` has mode
`0660 root:kvm`, so a plain `stat` succeeds even for a user who cannot use it.
A rootless podman deployment running as a service user outside the `kvm` group
runs into this. Without a check, the first sign is a qemu error in the
container's stderr, minutes into someone's first task. Add the service user to
the group:

```console
$ sudo usermod -aG kvm cloop      # then restart the service, so it re-reads its groups
```

cloop's preflight opens the device instead of only calling `stat` on it, so this
problem shows up before a run starts.

---

## Local: podman or docker

### 1. Install Kata

Use your distribution's package or the upstream release
(`kata-static-*.tar.xz` under
[kata-containers/releases](https://github.com/kata-containers/kata-containers/releases)).
The package usually installs `containerd-shim-kata-v2` and a `kata-runtime`
binary, and on many distributions it registers itself with docker for you.

### 2. Register it with the CLI

cloop passes the CLI a runtime name, never a path, and the CLI looks the name
up in a root-owned table, so the hub's configuration can't make a root daemon
run an arbitrary binary. Registering the runtime is a privileged step you do
once.

**docker**, in `/etc/docker/daemon.json`:

```json
{
  "runtimes": {
    "kata-qemu": { "path": "/usr/bin/containerd-shim-kata-v2" }
  }
}
```

```console
$ sudo systemctl restart docker
$ docker info --format '{{json .Runtimes}}'
{"io.containerd.runc.v2":{...},"kata-qemu":{...},"runc":{...}}
```

cloop's preflight runs that last command too, so if `kata-qemu` is not in its
output, cloop won't find it either.

**podman**, in `containers.conf` (`/etc/containers/containers.conf` system-wide,
or `~/.config/containers/containers.conf` for a rootless user):

```toml
[engine.runtimes]
kata-qemu = ["/usr/bin/containerd-shim-kata-v2"]
```

Podman has no equivalent of docker's Runtimes table (`podman info` reports only
the active runtime), so cloop can't list the runtimes podman would accept. The
preflight reports a warning that the name is unverified until the first run,
never a failure: cloop can't tell a missing runtime from one it can't list, and
a failure would stop a working deployment at startup.

### 3. Point cloop at it

In `.cloop/config.yaml`:

```yaml
executors:
  container:
    enabled: true
    runtime: docker
    oci_runtime: kata-qemu     # kata | kata-qemu | kata-clh | kata-runtime
    image: ghcr.io/blechschmidt/cloop-harness:latest
    cpus: 2
    memory: 2g
    network: none
```

You can also set it with
`cloop config set executors.container.oci_runtime kata-qemu`. Before you
restart the hub, note two things about the field:

- **It must be a name.** The validator allows only letters, digits, `.`, `_`
  and `-`, with no `/` or `\`, no leading dash, and at most 64 characters.
  Otherwise it accepts any name, because operators register Kata under many
  names.
- **A malformed value disables the container executor.** cloop doesn't reset it
  to the default, because that would fall back to runc and turn your VM sandbox
  into an ordinary container while everything kept reporting success. The
  startup log names the field and the reason.

---

## Verifying it

`cloop executor list` shows the sandbox type in its usual columns:

```console
$ cloop executor list
ID                   KIND           ISOLATION    EGRESS   NOTES
container            container      vm           no       default, docker via kata-qemu, ghcr.io/blechschmidt/cloop-harness:latest, hypervisor-backed
```

`cloop executor test <id>` is the real check. It adds two findings only when an
`oci_runtime` is configured, so a runc deployment's report doesn't change:

```console
$ cloop executor test container
cloop executor test — container (container)

Preflight
  ok   runtime      docker 27.3.1 at /usr/bin/docker
  ok   daemon       docker is responding
  ok   oci-runtime  kata-qemu is registered with docker
  ok   kvm          /dev/kvm is usable; kata-qemu workloads run in a VM with their own kernel
  ok   image        image ghcr.io/blechschmidt/cloop-harness:latest is present
  ok   network      network is disabled (--network=none)

Smoke test
  | cloop dev
  | Go go1.25.9 linux/amd64

OK — the sandbox ran the workload in 4.812s
  image:     ghcr.io/blechschmidt/cloop-harness:latest
  runtime:   docker
  container: cloop-…
```

The `runtime:` line names the container CLI, not the OCI runtime. The VM
sandbox shows up in the `oci-runtime` and `kvm` findings above, and afterwards
in `cloop executor list`.

Preflight only shows that the name resolves and the device opens, so it can't
prove a VM will boot. The smoke test can, because it starts a real container
under the configured runtime. If the preflight is all green but the smoke test
fails, Kata is registered and the host can open `/dev/kvm`, but the VM didn't
start: read the runtime's own stderr in the output.

Run the test after every change, because a failed check doesn't take the
executor out of service. An executor whose `kvm` check fails stays registered
as `degraded`, and degraded executors still get work. It keeps advertising
`hypervisor-backed`, a label that comes only from the configured name, so its
runs fail at start instead of at placement. `cloop hub doctor` and the startup
log show the same finding, but cloop doesn't fix it for you.

### The isolation probe checks the name for you

The hub doesn't trust the runtime's name alone. When the executor is
reconciled, when a device says hello, after the runtime changes, and daily, it
runs `cloop isolation-probe` under the configured runtime and compares what the
sandbox's kernel reports about itself with the host's own kernel. The probe is
a mode of the cloop binary, mounted read-only into the sandbox so the image
can't answer for it. A Kata guest has its own kernel and boot ID and QEMU's or
Cloud Hypervisor's firmware tables; a runc container reads the host's boot ID.
The verdict appears on the executor's card in the **Executors** panel:

| Card says | Meaning |
| --- | --- |
| `claims kata-qemu, verified: a virtual machine` | the probe found a guest kernel behind a hypervisor |
| `claims kata, runs on the host kernel` | the name is an alias for runc; projects requiring isolation are refused here |
| `claims kata, runs on a userspace kernel (gVisor)` | the name is an alias for runsc; there is no hypervisor |
| `claims kata, never verified` | no probe has completed; admitted with a warning unless `executors.isolation_evidence` is `required` |

Hover over the chip to see the evidence and when it was collected. **Re-probe**
runs the probe again, for example after you fix `daemon.json`. The same verdicts
appear in `cloop hub doctor` and **Settings → Hub health** as
`executors.isolation`, and each change of verdict is recorded in the audit trail
as `executor.isolation_verdict`.

To refuse executors whose claim was never verified, instead of warning about
them:

```yaml
executors:
  isolation_evidence: required    # default: warn
```

To see the difference yourself, compare the kernel versions on the host and in
a Kata container:

```console
$ uname -r                                    # on the host
6.8.0-137-generic
$ docker run --rm --runtime kata-qemu <image> uname -r
6.1.62                                        # the Kata guest kernel
```

---

## Kubernetes

On a cluster there is one more piece, and cloop doesn't manage it: a
**RuntimeClass**, a cluster-scoped object installed along with the Kata node
pool. cloop names a RuntimeClass but doesn't create one. The hub holds only a
namespaced Role in the workload namespace, so it can't read the RuntimeClass to
check it in preflight either.

### 1. Install Kata on the nodes

The usual way is `kata-deploy`, a DaemonSet that installs the runtime on
labelled nodes and creates the RuntimeClass objects (`kata-qemu`, `kata-clh` and
others). Managed Kubernetes services often have their own setting instead: GKE
and AKS both offer a Kata or "confidential" node pool option that does the same.

Check which RuntimeClasses the cluster has:

```console
$ kubectl get runtimeclass
NAME        HANDLER     AGE
kata-clh    kata-clh    3d
kata-qemu   kata-qemu   3d
```

### 2. Configure the executor

A RuntimeClass names a handler. It doesn't keep ordinary workloads off the Kata
pool, so those nodes are usually tainted. A Pod then needs a matching toleration
to be allowed onto them, and a node selector to be placed there. If you set only
`runtime_class` and the pool is tainted, your Pods stay unscheduled:

```yaml
executors:
  kubernetes:
    enabled: true
    namespace: cloop-workloads
    image: ghcr.io/acme/cloop-harness@sha256:…
    runtime_class: kata-qemu
    node_selector:
      katacontainers.io/kata-runtime: "true"
    tolerations:
      - key: kata
        operator: Exists
        effect: NoSchedule
```

Use the label and taint your node pool has. `kata-deploy` labels nodes
`katacontainers.io/kata-runtime=true`, but a managed pool uses its own.

The Helm chart's ConfigMap doesn't render `runtime_class`, `node_selector` or
`tolerations`, so with a chart-based install, set them directly in the hub's
`config.yaml`.

### 3. Verify

```console
$ cloop executor list
ID                   KIND           ISOLATION    EGRESS   NOTES
k8s-prod             kubernetes     remote       yes      hypervisor-backed
```

Isolation stays `remote`, because the workload still runs on a machine that
isn't the hub's. What's new is `hypervisor-backed`. `cloop executor test
k8s-prod` runs the usual Kubernetes preflight and then a real Pod. If the
cluster doesn't have the RuntimeClass, the test shows a Pod that never runs and
an error naming the class.

`cloop hub doctor` reports `virtualized` for each executor in its `executors`
group, which gives the same information in machine-readable form:

```console
$ cloop hub doctor --json | jq '.findings[] | select(.check=="executors") | .details'
```

---

## Remote executors (enrolled devices)

The troubleshooting table points here when the hub itself can't start a VM. In
this case the machine that needs `/dev/kvm` isn't the one you run commands on.
The hub never sees the device's hardware, so the device has to report it.

Set the sandbox on the executor instead of in `config.yaml`: an enrolled
device's sandbox is control-plane state, not part of a file on the hub. Use the
**Executors** panel, or the API:

```console
$ curl -X PUT https://hub.example.com/api/executors/$ID/sandbox \
    -H 'Content-Type: application/json' \
    -d '{"mode":"container","engine":"docker","runtime":"kata","image":"ubuntu:24.04"}'
```

Each time the device connects, it reports whether it can run that sandbox, and
the panel tells you before you commit to it:

```json
"warning": "This device reports no usable /dev/kvm, so the \"kata\" runtime
            cannot start a VM on it and dispatch here is refused."
```

When a device reports that it can't, two things happen:

- **It stops advertising the boundary.** `Virtualized` becomes false, so
  placement won't send work that requires a hypervisor here. For a Kata runtime,
  `KernelIsolated` becomes false too, because Kata's isolation comes from the
  guest kernel. It stays true for `runsc`, whose Sentry doesn't need `/dev/kvm`.
- **Dispatch is refused.** Otherwise the payload would reach the device, Kata
  would launch QEMU with `accel=kvm`, and about fifty seconds later the shim
  would give up with `timed out waiting for QMP ready: Connection refused`. That
  error mentions neither KVM, nested virtualization nor the executor, and it
  would recur on every dispatch.

There is no mode to fall back to. Kata always passes `accel=kvm`, and the QEMU
it bundles is built with `--disable-tcg`, so on a host without nested
virtualization `qemu-system-x86_64 -accel help` lists only `kvm`. Either the
device can start a VM or it can't.

An agent older than protocol v9 doesn't report this at all. cloop treats that
as *unknown*, not *no*: the device keeps its current behaviour, and the panel
and preflight say that cloop couldn't ask, without implying a hypervisor is
there. Upgrading the agent gives a real answer, and the preflight's fix names
the upgrade route that works from this hub (see
[Moving a device forward](../architecture/executors.md#moving-a-device-forward-which-remedy-works)).

> **If the device is a cloud instance, check this first.** Most hosted instance
> types don't pass the CPU's virtualization extensions through to the guest. If
> `grep -c vmx /proc/cpuinfo` returns `0` on the device, or `modprobe kvm_intel`
> fails with *Operation not supported*, nested virtualization is off at the
> hypervisor, and nothing you install inside the guest will change that. Use
> `runsc` for a kernel boundary without a VM, or move the work to a metal
> instance.

---

## Requiring it

Advertising a VM sandbox is separate from requiring one. Placement can require
virtualization (`Requirements.RequireVirtualization`). A candidate that shares
the executing machine's kernel is then refused under the constraint
`virtualization`, with a message naming the two config keys that fix it, and
the work doesn't fall back to a weaker sandbox.

This is a separate requirement, not another isolation level, because it cuts
across isolation levels: a local Kata container reports isolation `vm` and a
Kata Pod reports `remote`, and no set of isolation values selects those two
without also admitting every non-Kata remote executor. See
[Placement](../architecture/executors.md#placement).

The claim starts from the runtime's name, because a name is all the OCI and
RuntimeClass APIs expose. `kata`, `katacontainers`, `kata-*`, `kata.*` and
`io.containerd.kata.v2` are recognised, and every other name counts as not
virtualized. That includes gVisor's `runsc`: it is a stronger boundary than
runc, but it is a userspace kernel, not a virtual machine.

The [isolation probe](#the-isolation-probe-checks-the-name-for-you) then checks
the claim. If runc is registered under the name `kata`, the probe reads the
host's boot ID: the executor's card says *claims kata, runs on the host
kernel*, and a project requiring virtualization is refused there under the
constraint `isolation_evidence`, with the evidence quoted. A claim that hasn't
been verified yet is admitted with a warning on the run, unless
`executors.isolation_evidence` is `required`. On Kubernetes, a second Pod on the
same node, under the cluster's default runtime, reads the node's own kernel,
because the executor Role can't read Node objects. There, the probe is the cloop
in the executor's configured image, because a Pod can't be handed a file from
the hub.

---

## Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| `FAIL oci-runtime`: *docker does not know a runtime named "kata-qemu"* | not registered, or dockerd was not restarted | add it to `/etc/docker/daemon.json` under `"runtimes"` and `systemctl restart docker` |
| `warn oci-runtime`: *cannot enumerate podman's runtimes* | expected on podman, which can't list its runtimes | check the `[engine.runtimes]` entry by hand, or run the smoke test |
| `FAIL kvm`: *no such file or directory* | no `/dev/kvm`; nested virtualization is off | enable it on the instance, load `kvm_intel`/`kvm_amd`, or move Kata to a remote executor |
| `FAIL kvm`: *permission denied* | the service user is not in the `kvm` group | `usermod -aG kvm <user>`, then restart the service |
| The container executor is missing after startup | a malformed `oci_runtime` disables it (cloop doesn't fall back to runc) | read the startup log line and fix the name |
| Isolation still shows `container` | cloop doesn't recognise the name as Kata | use `kata`, `kata-qemu`, `kata-clh` or another `kata-*` name |
| Pods stay unscheduled after setting `runtime_class` | the Kata pool is tainted | add the matching `tolerations` and `node_selector` |
| Preflight green, smoke test fails | Kata is configured but the VM did not boot | read the runtime's stderr in the smoke test output; usually a missing hypervisor binary or a nested-virtualization limit |
| Card says *claims kata, runs on the host kernel* | the runtime named `kata` is runc: a `daemon.json` alias, or a RuntimeClass whose handler is runc | register the real Kata shim under that name, restart the engine, press **Re-probe** |
| Card says *not verified: the probe could not run* | the executor's image is missing, the device is offline, or its agent is older than the probe | hover over the chip for the reason; the device's card names the upgrade |
| `unknown config key "executors.container.oci_runtime"` | a cloop from before the key could be set (it was documented and enforced, but not settable) | upgrade, or set it by hand in `.cloop/config.yaml` |
| A remote executor's dispatch fails with *device cannot start a virtual machine* | the enrolled device reported no usable `/dev/kvm` | see [Remote executors](#remote-executors-enrolled-devices): enable nested virtualization on the device's host, or switch that executor to `runsc` |
| `timed out waiting for QMP ready: Connection refused` on a device | Kata couldn't start QEMU there, almost always because there is no `/dev/kvm` | upgrade the agent to v9 or later, so the hub refuses the dispatch up front and names the cause |

---

## See also

- [Executor architecture](../architecture/executors.md#virtualization-is-a-second-axis-not-a-fifth-value): how `Isolation` and `Virtualized` differ, and why
- [Configuration reference](../reference/configuration.md#vm-isolated-sandboxes-kata-containers): both keys in detail
- [Security model](../security/model.md#the-kernel-underneath-the-sandbox): what the hypervisor boundary protects, and what it leaves alone
- [Per-project sandbox](../reference/sandbox.md): what a spec committed to the repository can ask of an executor
