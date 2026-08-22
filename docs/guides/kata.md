# Running workloads in a VM (Kata Containers)

How to give cloop's sandboxes a kernel of their own, on a single host and on a
cluster — and how to tell whether it actually worked.

cloop's default sandbox is a container: namespaces, cgroups, seccomp and dropped
capabilities, all enforced by the kernel the workload is running on. That is the
right trade for most deployments. It is a thinner boundary than it looks when the
thing inside is model-authored code running on someone else's behalf, because a
local privilege escalation in that kernel is a compromise of the machine, not of
the sandbox.

[Kata Containers](https://katacontainers.io) boots each container inside a
lightweight VM. The workload gets its own guest kernel; the host's sits behind a
hypervisor. One kernel bug becomes a guest-kernel bug *plus* a hypervisor escape.

Two configuration keys turn it on, one per backend, and neither changes anything
for a deployment that leaves them empty:

| | Key | Effect |
| --- | --- | --- |
| local | `executors.container.oci_runtime` | podman/docker is invoked with `--runtime <name>` |
| cluster | `executors.kubernetes.runtime_class` | every workload Pod carries `runtimeClassName` |

Read [what this does and does not
change](../security/model.md#the-kernel-underneath-the-sandbox) before deciding
it solves a problem you have — egress, the shared workspace mount and the
credentials a workload holds are all exactly where they were.

- [Prerequisite: the host must be able to start a VM](#prerequisite-the-host-must-be-able-to-start-a-vm)
- [Local: podman or docker](#local-podman-or-docker)
- [Verifying it](#verifying-it)
- [Kubernetes](#kubernetes)
- [Requiring it](#requiring-it)
- [Troubleshooting](#troubleshooting)

---

## Prerequisite: the host must be able to start a VM

Kata needs `/dev/kvm`, and needs the user cloop runs as to be able to **open** it
read-write. Both halves fail in a way that is easy to miss:

```console
$ ls -l /dev/kvm
crw-rw---- 1 root kvm 10, 232 /dev/kvm
```

That listing is what a working host looks like. The two failures are:

**No `/dev/kvm` at all.** The overwhelmingly common cause on a hosted deployment
is that the hub is *itself* a VM and nested virtualization is off. It is a
per-instance property of the machine you rent, not something a package installs:

- **GCP** — the instance needs `--enable-nested-virtualization`, and the licence
  is set on the disk image;
- **AWS** — a `.metal` instance type, or one of the families that exposes
  nested virtualization;
- **Azure** — a size that supports it (`Dv3`/`Ev3` and later);
- **bare metal** — check that VT-x/AMD-V is enabled in firmware and that
  `kvm_intel` or `kvm_amd` is loaded.

If none of those is available, run Kata on a machine that is not the hub: an
enrolled remote executor, or a Kubernetes node pool.

**Present but not openable.** `/dev/kvm` is mode `0660 root:kvm` on most
distributions, so a plain `stat` succeeds for a user who cannot use it. A
rootless podman deployment running as a service user outside the `kvm` group hits
this, and the symptom without a check is a qemu error in the container's stderr
minutes into someone's first task:

```console
$ sudo usermod -aG kvm cloop      # then restart the service, so it re-reads its groups
```

cloop's preflight opens the device rather than stat-ing it, precisely so this
shows up before a run rather than during one.

---

## Local: podman or docker

### 1. Install Kata

Use your distribution's package or the upstream release
(`kata-static-*.tar.xz` under
[kata-containers/releases](https://github.com/kata-containers/kata-containers/releases)).
The package normally installs `containerd-shim-kata-v2` and a `kata-runtime`
binary, and on many distributions it registers itself with docker for you.

### 2. Register it with the CLI

cloop passes a **name**, never a path, and the CLI resolves that name against a
root-owned table. This is the indirection that keeps hub configuration from
naming an arbitrary binary for a root daemon to execute — so registration is a
deliberate, privileged step, done once.

**docker** — `/etc/docker/daemon.json`:

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

That last command is exactly what cloop's preflight runs, so if `kata-qemu` is
not in its output cloop will not find it either.

**podman** — `containers.conf` (`/etc/containers/containers.conf` system-wide, or
`~/.config/containers/containers.conf` for a rootless user):

```toml
[engine.runtimes]
kata-qemu = ["/usr/bin/containerd-shim-kata-v2"]
```

Podman has no equivalent of docker's Runtimes table — `podman info` reports only
the *active* runtime — so cloop cannot enumerate what podman would accept. It
says so rather than guessing: the preflight finding is a **warning** that the
name is unverified until the first run, never a failure. A check that cannot tell
"absent" from "unenumerable" must not report "absent", or a working deployment
fails at startup.

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

There is no `cloop config set` key for `oci_runtime`; edit the file. Two
properties of the field are worth knowing before you restart the hub:

- **It is a name, and the validator enforces that** — no `/` or `\`, no leading
  dash, letters, digits, `.`, `_` and `-` only, 64 characters at most. The shape
  check is permissive on purpose, because operators legitimately register Kata
  under many names.
- **A malformed value disables the container executor** instead of being cleared
  to the default. Clearing it would fall back to runc, quietly turning the VM
  sandbox you configured into a container one while everything kept reporting
  success. The startup log names the field and the reason.

---

## Verifying it

`cloop executor list` states the sandbox type in the columns it already had:

```console
$ cloop executor list
ID                   KIND           ISOLATION    EGRESS   NOTES
container            container      vm           no       default, docker via kata-qemu, ghcr.io/blechschmidt/cloop-harness:latest, hypervisor-backed
```

`cloop executor test <id>` is the real check. Two extra findings appear when —
and only when — an `oci_runtime` is configured, so a runc deployment's report is
unchanged:

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

The `runtime:` line there names the **CLI**, not the OCI runtime — the
`oci-runtime` and `kvm` findings above are where the VM sandbox shows up, and
`cloop executor list` is where it shows up afterwards.

Preflight cannot prove a VM will boot — it proves the name resolves and the
device opens. **The smoke test is the proof**: it starts a real container under
the configured runtime, and either the VM comes up or it does not. A preflight
that is all green and a smoke test that fails means Kata is registered and the
host can open `/dev/kvm`, but the VM itself did not start; the runtime's own
stderr in that output is the thing to read.

Run it after every change, because a failed check is a *finding*, not a
retraction. An executor whose `kvm` check fails is registered and `degraded`, and
degraded executors are still scheduled onto — it goes on advertising
`hypervisor-backed`, since that claim comes from the configured name and nothing
else, and its runs fail at start rather than at placement. `cloop hub doctor` and
the startup log carry the same finding, so this is visible without asking; it is
just not self-correcting.

A last check from inside, if you want to see it rather than infer it — the guest
kernel is not the host's:

```console
$ uname -r                                    # on the host
6.8.0-137-generic
$ docker run --rm --runtime kata-qemu <image> uname -r
6.1.62                                        # the Kata guest kernel
```

---

## Kubernetes

The cluster-side path has one more moving part, and cloop owns none of it: a
**RuntimeClass** is a cluster-scoped object installed alongside the Kata node
pool. cloop names one; it does not create one, and because the hub deliberately
holds only a namespaced Role in the workload namespace, it cannot even read one
to preflight it.

### 1. Install Kata on the nodes

`kata-deploy` is the usual mechanism — a DaemonSet that installs the runtime onto
labelled nodes and creates the RuntimeClass objects (`kata-qemu`, `kata-clh`, and
friends). Managed offerings often have their own switch instead; GKE and AKS both
expose a Kata/"confidential" node pool option that does the same thing.

Confirm what the cluster ended up with:

```console
$ kubectl get runtimeclass
NAME        HANDLER     AGE
kata-clh    kata-clh    3d
kata-qemu   kata-qemu   3d
```

### 2. Configure the executor

A RuntimeClass names a handler. It does **not** keep ordinary workloads off the
Kata pool, so those nodes are conventionally tainted — which means a Pod needs a
matching toleration to land there at all, and a node selector to be steered there
rather than merely permitted. Set `runtime_class` alone against a tainted pool
and your Pods will sit unscheduled:

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

Match the label and taint your node pool actually carries — `kata-deploy` labels
nodes `katacontainers.io/kata-runtime=true`, but a managed pool will use its own.

The Helm chart's ConfigMap does not render `runtime_class`, `node_selector` or
`tolerations`, so a chart-based install sets them in the hub's `config.yaml`
directly.

### 3. Verify

```console
$ cloop executor list
ID                   KIND           ISOLATION    EGRESS   NOTES
k8s-prod             kubernetes     remote       yes      hypervisor-backed
```

Isolation stays `remote` — the machine is still not the hub's, and that has not
changed — and `hypervisor-backed` is the part that has. `cloop executor test
k8s-prod` runs the usual Kubernetes preflight and then a real Pod; a
RuntimeClass the cluster does not have shows up there, as a Pod that never runs
and a rejection naming the class.

`cloop hub doctor` reports `virtualized` per executor in its `executors` group,
which is the machine-readable form of the same fact:

```console
$ cloop hub doctor --json | jq '.findings[] | select(.check=="executors") | .details'
```

---

## Requiring it

Advertising a VM sandbox and *demanding* one are different things. Placement can
require virtualization (`Requirements.RequireVirtualization`), and a candidate
that shares the executing machine's kernel is then refused under the constraint
`virtualization`, with a message naming the two config keys that fix it — rather
than being quietly run on a weaker sandbox.

It is a separate requirement from isolation rather than another isolation level
because it cuts across it: a local Kata container reports isolation `vm` and a
Kata Pod reports `remote`, and no set of isolation values selects exactly those
two without also admitting every non-Kata remote executor. See
[Placement](../architecture/executors.md#placement).

One honest limit, worth stating before you build policy on it: the claim is
derived from the runtime **name** and nothing else, because a name is all the OCI
and RuntimeClass APIs expose. `kata`, `katacontainers`, `kata-*`, `kata.*` and
`io.containerd.kata.v2` are recognised; everything else is false, including
gVisor's `runsc`, which is a stronger boundary than runc but is a userspace
kernel rather than a virtual machine and would be misdescribed as one. Register
runc under the name `kata` and cloop will believe you.

---

## Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| `FAIL oci-runtime` — *docker does not know a runtime named "kata-qemu"* | not registered, or dockerd was not restarted | add it to `/etc/docker/daemon.json` under `"runtimes"` and `systemctl restart docker` |
| `warn oci-runtime` — *cannot enumerate podman's runtimes* | expected on podman; it cannot be asked | confirm the `[engine.runtimes]` entry by hand, or run the smoke test |
| `FAIL kvm` — *no such file or directory* | no `/dev/kvm`; nested virtualization is off | enable it on the instance, load `kvm_intel`/`kvm_amd`, or move Kata to a remote executor |
| `FAIL kvm` — *permission denied* | the service user is not in the `kvm` group | `usermod -aG kvm <user>`, then restart the service |
| The container executor vanished at startup | a malformed `oci_runtime` disables it rather than falling back to runc | read the startup log line, fix the name |
| Isolation still reads `container` | the name is not one the matcher recognises as Kata | use `kata`, `kata-qemu`, `kata-clh` or another `kata-*` name |
| Pods stay unscheduled after setting `runtime_class` | the Kata pool is tainted | add the matching `tolerations` and `node_selector` |
| Preflight green, smoke test fails | Kata is configured but the VM did not boot | read the runtime's stderr in the smoke output; usually a missing hypervisor binary or a nested-virtualization limit |

---

## See also

- [Executor architecture](../architecture/executors.md#virtualization-is-a-second-axis-not-a-fifth-value) — how `Isolation` and `Virtualized` differ, and why
- [Configuration reference](../reference/configuration.md#vm-isolated-sandboxes-kata-containers) — both keys, key by key
- [Security model](../security/model.md#the-kernel-underneath-the-sandbox) — what the hypervisor boundary is worth, and what it leaves alone
- [Per-project sandbox](../reference/sandbox.md) — what a repo-committed spec may ask of an executor
