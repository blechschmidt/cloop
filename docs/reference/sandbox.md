# Per-project sandbox: `.cloop/sandbox.yaml`

A hub's `executors.container.image` sets one image for every project on the
hub. That works on a laptop, but not on a hub shared by several teams: a
repository that needs a different runtime can't run in a sandbox unless an
operator edits the hub's configuration.

`.cloop/sandbox.yaml` lets the repository describe its own environment. The
operator still decides which executors exist, what they can reach and what the
resource ceilings are, and the project describes the environment within those
limits.

- [Schema](#schema)
- [What a spec can and cannot do](#what-a-spec-can-and-cannot-do)
- [`resources.disk` and the workspace](#resourcesdisk-and-the-workspace)
- [The published images, and what an image carries](#the-published-images-and-what-an-image-carries)
- [Image trust policy](#image-trust-policy)
- [Executor support](#executor-support)
- [Reproducibility](#reproducibility)
- [Errors](#errors)

## Schema

Every key is optional. If the file is missing or contains only comments, the
executor's defaults apply, so you don't need the file to use cloop.

```yaml
# The image this project's tasks run in. Digest-pinned at start; see
# Reproducibility below.
image: ghcr.io/acme/python-toolchain:3.12

# Commands baked into a derived image once per unique (image, setup) pair.
# Not re-run per task. Requires an executor that can build.
setup:
  - pip install --no-cache-dir -r requirements.txt
  - apt-get update && apt-get install -y --no-install-recommends ripgrep

# An allowlist of environment variable NAMES to forward. Never values: a name
# the project holds no grant for forwards nothing.
env:
  - ANTHROPIC_API_KEY
  - GITHUB_TOKEN

# Per-task resource *requests*. Clamped to the hub's ceilings, not honoured
# beyond them; a clamp is recorded as a warning rather than an error. Omitting a
# key does not mean "the default" — it means no limit, so the hub's ceiling
# applies to it too. See "resources: what you ask for vs what you get" below.
resources:
  cpu: 2          # cores; 0 or absent means no limit of your own
  memory: 4g      # 512m, 2g, 1024k, or a bare integer read as megabytes
  pids: 512       # process/thread cap
  disk: 2g        # the workspace, and what a run adds to .cloop/; also bounds a fetched tree

capabilities:
  git: true       # the sandbox needs a working git
  network: egress_2f1c9a4e7b3d05286af1c0d4   # the ID of an egress grant this
                  # project holds; `cloop egress list` prints it. Not the
                  # --scope label ("ci", "deps") — that is never matched.
  virtualized: true       # only run behind a hypervisor (Kata); never share a kernel
  kernel_isolated: true   # weaker and usually what you want: gVisor *or* Kata
  egress: public          # public Internet only; drop all private address space
  devices: [serial0]      # select from the host_device grants this project holds
  interfaces: [dut]       # select from the host_interface grants this project holds

# Re-expose a sub-path of the workspace at another path inside the sandbox.
# Sources are workspace-relative; targets are absolute.
mounts:
  - source: .cache/pip
    target: /home/agent/.cache/pip
  - source: vendor
    target: /opt/vendor
    read_only: true
```

The schema is **closed**: an unknown key is an error. Otherwise a misspelt
`resource:` key would be ignored, and the project would run without limits
while its author believed it was capped.

### Bounds

| Field | Bound | Over the bound |
| --- | --- | --- |
| `resources.cpu` | ≤ 1024 cores | clamped, with a warning |
| `resources.memory` | 64 MB – 1 TiB | above: clamped; below 64 MB: error |
| `resources.pids` | 1 – 65536 | clamped; `-1` (unlimited) is refused |
| `resources.disk` | 64 MB – 1 TiB | above: clamped; below 64 MB: error |
| `setup` | 32 commands, 4096 bytes each | error |
| `env` | 64 names | error |
| `mounts` | 16 entries | error |
| file size | 64 KiB | error |

Numbers out of range are clamped instead of refused, because the author can't
know the hub's ceilings. The run starts at the limit and logs a warning.
Malformed values are still errors: `2gb`, for example, is refused.

## What a spec can and cannot do

The file comes in with `git pull`. Anyone who can open a pull request can
propose changes to it, and on a hub, whoever merges it is not the person whose
infrastructure runs it. The rules below follow from that.

A spec can only remove access. It can never add any.

| | |
| --- | --- |
| **Network** | Without `capabilities.network`, the run gets `--network=none`, whatever the executor is configured with. Naming a grant doesn't turn the network on. It states that the project already holds the grant with that ID, and the executor's own network setting stays as it is. No field adds egress. The value is compared with `Grant.ID` (the minted `egress_…` string), never with the `--scope` label, so a human-friendly name here gets the run denied. The run then gets a session on the hub's egress proxy under that grant, with `HTTPS_PROXY` in its environment. If the hub can't provide the session (it has no proxy, or the bound executor has no route to it), the run is refused (see [Scoped network egress](configuration.md#scoped-network-egress)). |
| **Secrets** | `env` filters the environment the hub has already built from the project's grants. A name the project has no grant for forwards nothing. Values aren't allowed in this file: `FOO=bar` is an invalid entry. |
| **Filesystem** | `mounts.source` is relative to the workspace. It can't be absolute or contain `..` or a colon (a colon would add options to the runtime's `-v` flag). Sources are checked again after symlinks are resolved, so a symlink in the repository that points at `/etc` is rejected too. |
| **Privilege** | Nothing in the schema grants capabilities, changes the UID or disables seccomp. The Dockerfile generated for `setup:` contains only `FROM`, `LABEL` and `RUN` (no `COPY`, `USER` or `ENV`), so a repository can't put its own files or a privileged user into a cached image that later tasks use. |
| **Build-time network** | A `setup:` build has the same network access as the run. A spec without an egress grant builds with `--network=none`, so `setup:` can't reach the Internet on a deployment where runs can't. |
| **Virtualization** | `capabilities.virtualized` is a boolean. It asks for a stronger boundary than the executor would otherwise use, so it needs no grant. It can't turn a runc executor into a Kata one; it only refuses to run on one. `capabilities.kernel_isolated` works the same way but is weaker: gVisor satisfies it as well as Kata. Use it unless you specifically need a hypervisor. See [the Kata guide](../guides/kata.md). |
| **Egress scope** | `capabilities.egress` takes `public` or `none`, never an address list. Both values remove access, so neither needs a grant, and there is no `allow_cidrs` key. To reach private addresses, use `capabilities.network` with an egress grant from an operator. On an executor whose sandboxes can reach only an egress broker, `public` would add access, so it is refused there instead of being downgraded. |
| **Interfaces** | `capabilities.interfaces` selects, by name, from the `host_interface` grants the project already holds. It works like `capabilities.devices`, with more at stake: a granted interface is moved into the sandbox's network namespace, so the executor can't use it while the task runs. As with devices, no key names an interface directly, because a file that arrives in a pull request must not be able to take an interface away from the host. Naming an ungranted interface returns 409. |
| **Devices** | `capabilities.devices` selects, by name, from the `host_device` grants the project already holds. No key takes a device path, for the same reason `mounts.source` can't be absolute: the file contains whatever a pull request puts in it, and a device node gives control over part of the machine. Naming an ungranted device returns 409 instead of running without it, because a task that needs a device can't do anything useful without it. |
| **Resources** | `resources` is a request, capped by the hub's [fleet and per-project ceilings](configuration.md#resource-ceilings). It can't raise either, and leaving a key out doesn't avoid them: without `resources.memory` the project sets no limit of its own, so the executor's default applies and the ceiling caps that. A request above a ceiling is lowered, and the reduction is logged in the project's event journal. It is not an error: the run gets a smaller sandbox. |

Without an `env:` key, the environment is passed through unchanged. A missing
key is not treated as an empty allowlist, which would remove the API key from
every project that adds a `sandbox.yaml` only to pin an image.

### `resources.disk` and the workspace

`disk` limits the **workspace**: the directory tree the workload works in, which
is where a sandbox's writes reach the host's disk. The image's root filesystem
is mounted read-only and `/tmp` is a size-capped `tmpfs`. The workspace is the
project directory bind-mounted at `/workspace`, a device's workspace directory,
or, for a feature, the staged checkout plus the output directory its results
come back through. The project's `.cloop/` directory as it was when the workload
started doesn't count (it is the hub's bookkeeping), but anything the run adds
to it does, because the sandbox can write there through the same bind mount.

It doesn't limit an anonymous volume the engine creates for an image's `VOLUME`
declaration, or a read-write repository mount from a `local_repo` grant. Neither
is part of the workspace.

The limit is applied twice, by two mechanisms that complement each other:

- **After a fetch** (`Workspace.SizeLimitMB`). When an executor has to fetch the
  source tree (a Kubernetes Pod, a remote agent, anything that doesn't share the
  hub's filesystem), the provisioner measures what it fetched. If the tree is
  larger than the limit, the run doesn't start, and the error names the limit.
  Without this check the run would fail part-way with an error about the
  repository.
- **While the workload runs** (`ResourceLimits.DiskMB`). Each executor enforces
  it in its own way, and its card in the Executors panel says how:

| Executor | Card | How |
| --- | --- | --- |
| `kubernetes` | `disk: enforced (eviction)` | the Pod's ephemeral-storage limit and the workspace `emptyDir`'s `sizeLimit`; the kubelet evicts a Pod that outgrows them |
| `container`, and a `remote` device or virtual executor running payloads in a container | `disk: enforced (sampled)` | the driver measures the workspace and stops the workload once it is over the limit (see below) |
| `localprocess`, a device running payloads on its host, a device whose agent predates protocol v20 | `disk: not supported` | nothing. A spec that sets `resources.disk` is refused at placement, with constraint `resource_limits` where the executor enforces no limits at all, or `disk_limit` where it enforces the other limits (an agent older than v20) |

#### How the container driver holds it

`--storage-opt size=` limits a container's writable layer, but here that layer
is read-only and the work goes elsewhere. So the driver limits the workspace by
measuring it:

- **At the start**, before anything is provisioned, it measures the tree. If the
  tree is already over the limit, the workload doesn't start, and the error gives
  both sizes and says how to raise the limit. This is the same check the
  provisioner makes after a fetch, applied to a tree that was already there:

  ```
  executor container: refusing to start: the workspace /srv/projects/api already
  holds 73 MB, over this workload's disk limit of 64 MB (from .cloop/sandbox.yaml
  resources.disk); free space in the workspace, or raise resources.disk in
  .cloop/sandbox.yaml (an operator's disk ceiling still caps it)
  ```

  The refusal is recorded in the project's journal as a `disk_limit` row. If the
  tree can't be measured within 30 seconds, the workload starts anyway, and its
  usage is unknown until the first sample.
- **While it runs**, it measures again: first 15 seconds after the start
  measurement, then every 5 seconds to 2 minutes, more often the sooner the tree
  would reach the limit at its current growth rate. The interval is never less
  than ten times the duration of the last walk, so a tree that is expensive to
  measure is measured less often. Each walk runs on its own thread at the lowest
  CPU priority and in the idle I/O class, one per workload at a time, and is
  abandoned after a minute. The limit, and any stop in progress, are stored with
  the workload's handle, so a restarted hub keeps measuring the containers it
  adopts.
- **Past the limit**, the workload is stopped with SIGKILL (a grace period would
  only let it write more), and its status records outcome `disk_limit` with the
  measured and allowed sizes. The hub then pauses the run with reason
  `disk_limit` instead of retrying it. It returns the running task to pending,
  with a note from cloop giving both sizes, and writes a `disk_limit` row to the
  journal. The task's `task.finish` audit row carries `stop: disk_limit`,
  `disk_used_mb` and `disk_limit_mb`. To continue, free space in the workspace or
  raise the limit, then press **Run**. A workspace that is still over the limit
  is refused at the start, so pressing Run without doing either doesn't start a
  loop.

A measurement counts allocated size, as `du` does: the blocks that files occupy
(a sparse file counts only the blocks it uses), each hard-linked file once, and
symlinks as themselves, never followed. Nothing below a mount point is counted.
A mount point here means a directory listed in the mount table, so a btrfs
subvolume, which has its own device number and can be created without
privileges, is counted. The walk uses directory descriptors instead of paths, so
deep nesting can't hide part of the tree from it. If a walk misses its deadline
or finds a directory its user can't read, the workload's output logs the usage
as **unknown**, never as under the limit. The partial count is a lower bound, so
it still stops a workload whose visible tree is already over the limit. Kata and
gVisor sandboxes write to the same bind mount, so measuring from the host is
still correct with them.

For a feature, the output directory counts too: the project state the hub
seeded, and the bundle the run's work comes back in, which is written at the
very end. A feature that finishes close to its limit can be stopped while
writing that bundle, and then its work is lost. Leave room for its diff.

This is enforcement by measurement, not a filesystem quota. Between two samples,
a burst of writes can overshoot the limit by the write rate times the sampling
interval, which on a fast disk can be gigabytes. The free-space floor
(`orchestrator.min_free_disk_mb`, see
[configuration](configuration.md#free-space-floor)) is what stops such a burst
from filling the volume that everything else uses.

#### The operator's disk ceiling

An operator's disk ceiling works like the memory ceiling. It can be the fleet's
`executors.limits.max_disk`, an executor's Limits in the Executors panel, or a
per-project ceiling. A `resources.disk` above the ceiling is lowered to it, and
a project that sets none gets the ceiling as its limit, so the ceiling also
covers projects that asked for nothing. A device can't read the hub's ceilings,
so the hub writes them into the spec it dispatches. It includes the disk ceiling
only for agents at protocol v20 or later, which enforce it; an older agent would
refuse the run. Where a disk ceiling is in force but the executor can't enforce
it, every dispatch records this in the project's journal (`resource_ceiling`),
and the executor's Limits dialog shows a warning when the ceiling is set.

`disk` doesn't request a workspace. Nothing in the schema names a repository or
adds a workspace placement requirement: a committed file that could arrange its
own clone could also supply the URL, in the same pull request. The hub decides
the kind of workspace, and a spec can only limit a fetch the hub has already
decided to make.

## The published images, and what an image carries

An image must contain the agent CLI that the project's provider uses: `claude`
for `claudecode`, `copilot` for `copilot`. This repository publishes two images,
built from the same Dockerfile. They differ in one program:

| Image | Carries | Use it for |
| --- | --- | --- |
| `ghcr.io/blechschmidt/cloop-harness` | `claude`, `cloop`, `git` | `claudecode` projects. The default for `executors.container.image`, a Kubernetes executor's image, and a device's container sandbox when it names none |
| `ghcr.io/blechschmidt/cloop-harness-copilot` | `claude`, `copilot`, `cloop`, `git` | `copilot` projects; it runs `claudecode` projects too |

Both are published for `linux/amd64` and `linux/arm64`, run under any UID, and
are tagged like the hub: `:latest` moves with each release, `:edge` with main,
and each release has its own tag. The copilot variant's first `:latest` was
built from main, because the variant didn't exist before the release that added
it.

**Why a variant.** The GitHub Copilot CLI is a 199 MB native binary that unpacks
its own 247 MB runtime the first time it starts. Measured on amd64 with CLI
1.0.104:

| | unpacked | compressed (pulled) |
| --- | ---: | ---: |
| `cloop-harness` | 685 MB | 268 MB |
| the Copilot CLI added | +445 MB (+65%) | +217 MB (+81%) |
| `cloop-harness-copilot` | 1,130 MB | 486 MB |

In the default image, the CLI would nearly double the download for every node
and every `claudecode` project, which is most projects. So it is in a separate
variant that you choose for `copilot` projects.

**What the copilot variant does differently.** The CLI comes from npm
(`@github/copilot`). It is pinned by version and by the sha512 integrity hash of
every tarball the install unpacks, and is installed offline from those checked
tarballs only. `scripts/copilot-cli-pins.sh <version>` prints the pins for a
newer version. The runtime is unpacked at build time into
`/usr/local/lib/copilot` (`COPILOT_PKG_CACHE_HOME`), read-only, so starting the
CLI writes nothing to the sandbox's `/tmp`. That is a 512 MB tmpfs in RAM, which
the 247 MB runtime would otherwise half fill on every task. `COPILOT_HOME` is
`/tmp/.copilot`, which any UID the sandbox runs as can write, and
`COPILOT_AUTO_UPDATE` is `false`, so a run uses the CLI version the image was
built with.

**The label.** An image lists the programs it carries in a label:

```
org.cloop.harnesses=claude,copilot,cloop,git
```

Wherever the hub already has an image's configuration, it reads the label
before the run starts. If the label doesn't list the project's harness, the run
is refused with `409 sandbox_image_lacks_harness`, and the error names the image
and an image that does carry the harness. The hub checks in two places:

- a **container executor** (the hub's own, a device's in container mode, or one
  reached through a virtual executor) inspects every image before running it,
  so it checks the label there, before any container exists. A device agent
  built before this check was added doesn't make it.
- under [`require_signature`](#signatures), the hub resolves a project's
  `image:` at its registry to verify the digest, and reads that digest's label
  before anything is leased for the run.

An image without the label is never refused for that reason. Almost no image has
one, including earlier releases of the published images, and a missing label
says nothing about what the image carries. A Kubernetes executor has no image
store the hub can read, so it doesn't check. To have your own image checked,
label it with the programs on its `PATH`:

```dockerfile
LABEL org.cloop.harnesses="claude,cloop,git"
```

## Image trust policy

The restrictions above don't cover `image:`, because the image is the sandbox's
whole environment. Its entrypoint, libraries and `PATH` are what the harness
runs in, and every credential the hub injects at start is handed to it. A pull
request that chooses the image chooses the code that runs, however many
capabilities are dropped around it.

So the operator restricts which images a project may name, for the whole hub,
under `sandbox.image_policy` in `config.yaml`:

```yaml
sandbox:
  image_policy:
    # Registry hosts a project may pull from. Also accepts "*.example.com"
    # (subdomains, at a label boundary) and "*" (any registry).
    allowed_registries:
      - ghcr.io

    # Optional: narrow to particular repositories. A trailing "/*" matches at
    # a path-component boundary.
    allowed_repos:
      - ghcr.io/acme/*

    # Refuse a reference pinned only to a tag.
    require_digest: true

    # Refuse an image cosign cannot verify. Needs the cosign binary on the hub,
    # which the published hub image bundles.
    require_signature: false
    cosign_public_keys:
      - /etc/cloop/cosign/acme.pub
    cosign_identities:
      - issuer: https://token.actions.githubusercontent.com
        subject_regexp: ^https://github\.com/acme/.+

    # Qualify a reference that names no registry. Unset, "alpine:3" is refused.
    default_registry: ""

    # Hold the operator's own images to these rules too (see below).
    govern_operator_images: false
```

Each rule you configure denies by default: with `allowed_registries` set, any
registry not on the list is refused. Without the section, nothing is
restricted. That is the default for a single developer, so a laptop's
`image: python:3.12` keeps working after an upgrade. Only the rules you set
apply, so `require_digest` on its own is a valid policy: any registry, as long
as the image is pinned by digest.

The policy applies to images a project names. `executors.container.image`,
`executors.kubernetes.image` and a device's or virtual executor's sandbox image
are chosen by the operator, the same person who writes the policy, so checking
them against it would add little. They run as configured unless
`govern_operator_images: true` holds them to the same registry, digest and
signature rules.

**cloop's own images.** These are checked whoever chose them.
`ghcr.io/blechschmidt/cloop`, `cloop-harness` and `cloop-harness-copilot` (the
default image is one of them) are signed by the workflow that publishes them.
Before a sandbox runs one of them, the hub verifies it against that workflow's
identity and dispatches the digest it verified. This applies whether the image
is the default, configured for an executor, a device's image or named by a
project. If a signature is present but wrong, the run is refused. An unsigned
image, or one that couldn't be checked, runs with a warning unless
`executors.image_provenance` is `required`. `govern_operator_images` doesn't
apply to them, because they are pinned separately. See
[Image provenance](configuration.md#image-provenance).

### Matching is on the parsed reference

Every comparison uses the reference after it has been parsed into registry,
repository, tag and digest, never the raw string. With
`allowed_registries: [ghcr.io]`, all of these are refused:

| Reference | Actually pulls from | Why a naive check passes it |
| --- | --- | --- |
| `evil.example/ghcr.io/tools` | `evil.example` | the allowed name appears as a repository path |
| `ghcr.io.evil.example/tools` | `ghcr.io.evil.example` | the allowed name appears as a domain prefix |
| `notghcr.io/tools` | `notghcr.io` | the allowed name is a suffix |
| `ghсr.io/tools` | whatever its owner points it at | the `с` is Cyrillic and looks the same |

Because of the last row, the whole reference must be ASCII. The OCI grammar
only allows ASCII, so a non-ASCII byte is refused as malformed. This one rule
excludes every lookalike character, and the punycode a Unicode-aware normalizer
would produce from them, without having to list lookalikes.

Likewise, `allowed_repos: [ghcr.io/acme/*]` matches `ghcr.io/acme/tools` and
`ghcr.io/acme/tools/nested`, but not `ghcr.io/acme-evil/tools`.

### Digests, and why a tag is not enough

`require_digest` refuses `image: ghcr.io/acme/tools:3.12`. When it is off and a
tag is accepted, the container executor resolves the tag to a digest and runs
the digest. The tag is resolved before anything is inspected, built or started,
so moving the tag between the check and the pull can't change what runs.

The Kubernetes executor has no image store of its own (a cluster's images
belong to its nodes), so it asks the registry the kubelet will pull from.
Before a Pod is built, every tag it would carry (the project's image,
`executors.kubernetes.image`, or one of cloop's own) is resolved to the digest
the registry serves at that moment, and the Pod carries `repo@sha256:…`.
Whenever the Pod is scheduled, the kubelet pulls that digest, however the tag
has moved since. For a private registry, the hub uses the login in
`executors.kubernetes.registry_secret` (a registry secret the hub keeps for
itself, never the namespace's `imagePullSecrets`); otherwise it asks
anonymously.

If the hub can't resolve a tag (the registry is unreachable from the hub, or
private with no login for it), `require_digest` and `require_signature` refuse
the run, and the error names the registry and what to do. Without either, the
tag goes into the Pod as written, with a warning in the run's log, and for that
run the tag could still move before the pull. So on Kubernetes you no longer
need `require_digest` to pin images, and the Helm chart leaves it off. What it
still does is make every project's `image:` name an exact image, and refuse an
unresolvable tag instead of warning.

A device in container mode, and a virtual executor, run images from the
device's own store, which the hub can't read either. Without
`require_signature`, the hub sends the reference the policy checked (with
`default_registry` added where the policy applied it), and the device's
container driver pins the tag in its own store, as the container executor does.
Under `require_signature`, the hub resolves the tag at its registry and sends
the device the digest it verified (see below). The device's engine never pulls,
so it either runs that image or refuses with an error naming the `pull`
to run for that digest.

An accepted digest reference is reduced to its canonical form,
`repo@sha256:…`. A `repo:tag@sha256:…` reference resolves to the same image, but
keeping both forms would make one image appear under two names in Pod specs,
audit rows and artifacts. The text as written is kept in the task artifact's
`sandbox_image_requested`.

### Signatures

`require_signature` verifies the image with [cosign](https://docs.sigstore.dev/cosign/),
against `cosign_public_keys` (`cosign verify --key`) or `cosign_identities`
(keyless, `--certificate-oidc-issuer` + `--certificate-identity-regexp`). A
signature from any one configured key or identity is enough. Listing two is for
a key rotation or two trusted publishers; it doesn't require both.

Signatures are verified with the cosign on the hub's `PATH`, wherever the image
runs. The container and Kubernetes executors verify their own workloads'
images. For a device or a virtual executor, the hub verifies the project image
before dispatch, because the agent applies no policy. A hub that serves a fleet
of devices therefore needs cosign even if none of its own executors runs
images, and it needs a route to the registries the policy names. To verify a
tag, the hub first asks the registry which digest the tag points to, using the
login for that registry from the Docker configuration of the hub's user
(`$DOCKER_CONFIG/config.json` or `~/.docker/config.json`,
`$REGISTRY_AUTH_FILE`, podman's `auth.json`). Credential helpers are not run.
An image pinned by digest needs no lookup.

Two more rules:

- **Verification is on the digest, never on a tag.** A signature checked against
  a tag only verifies what the tag pointed to during the check. So under
  `require_signature`, an image that can't be pinned (for example, one built
  locally, with no registry digest) is refused.
- **Without cosign, every image is refused.** A hub that requires signatures
  but has no cosign installed refuses every project image, with an error
  explaining how to install it. Otherwise the hub would report every image as
  fine without verifying any.

`cosign_identities` requires `subject_regexp`. An issuer alone would trust every
workflow at that provider, including workflows in repositories you don't know.

Successful verifications are cached for an hour per policy and digest, so a
project running one image all day spawns cosign once. Editing the policy
changes the cache key. Failures are never cached.

### Denials

Each refusal names the rule that caused it, with a remediation for whoever can
fix it:

| Rule | Meaning |
| --- | --- |
| `reference-syntax` | not a usable image reference (includes non-ASCII) |
| `unqualified-reference` | names no registry and the hub sets no `default_registry` |
| `registry-allowlist` | the registry is not on `allowed_registries` |
| `repository-allowlist` | the repository is not on `allowed_repos` |
| `digest-required` | pinned to a tag under `require_digest` |
| `digest-resolution` | had to be pinned and could not be |
| `signature-required` | `require_signature` is on and verification did not pass |
| `policy-configuration` | the policy itself is unusable |

The check runs in four places, all applying the same rules:

1. **`.cloop/sandbox.yaml` validation**, so a bad image shows up in the UI as a
   configuration error before a run starts, instead of as a container that
   fails to launch. If the hub's configuration doesn't load, the image is
   refused here (`policy-configuration`) instead of being checked against no
   policy.
2. **The container executor**, before the image is pulled, inspected or run.
3. **The Kubernetes pod builder**, before the reference goes into the Pod spec
   sent to the API server.
4. **The hub's driver for a device or a virtual executor**, before the start
   frame is sent. The container driver on the device applies no policy, so this
   is where a device's image is checked, including its signature. The driver
   reads the policy on each dispatch and refuses if the configuration doesn't
   load.

The executors make the final decision, since they run the image. The validation
step exists so that the error comes early and points at the file. None of the
four checks applies the policy to an image the operator configured for an
executor (`executors.*.image`, or a device's or virtual executor's sandbox
image), because the operator chose it alongside the policy.

Every denial is written to the audit trail as `sandbox.image_denied`, with the
project, the reference as written (not normalized, which could hide a lookalike
character), the rule, and the parsed registry and repository. The records are
most useful for spotting patterns, such as the same unknown registry named by
six projects within an hour.

## Executor support

Before the run starts, a spec is matched against the executor's advertised
capabilities, using the same matcher as the scheduler
([`pkg/executor/placement.go`](../../pkg/executor/placement.go)). If the spec
asks for something the executor can't do, it is refused with an error naming
the constraint. A spec is never partly applied.

| | `container` | `kubernetes` | `remote` | `localprocess` |
| --- | --- | --- | --- | --- |
| `image` | ✅ | ✅ | ✅ in container mode | ❌ |
| `setup` | ✅ | ❌ | ✅ in container mode | ❌ |
| `mounts` | ✅ (bind) | ✅ (`subPath`) | ❌ | ❌ |
| `resources` | ✅ | ✅ (no `pids`) | ✅ in container mode | ❌ |
| `resources.disk` | ✅ sampled | ✅ eviction | ✅ sampled, in container mode on agent ≥ v20 | ❌ |
| `capabilities.network` off | ✅ enforced | ⚠️ label only | ❌ | ❌ |
| `capabilities.virtualized` | ✅ with `oci_runtime` | ✅ with `runtime_class` | ✅ in container mode with a kata runtime, on a device with `/dev/kvm` | ❌ |
| `capabilities.kernel_isolated` | ✅ with `oci_runtime` (`runsc` or kata) | ✅ with `runtime_class` | ✅ in container mode with `runsc` or kata | ❌ |
| `capabilities.egress: public` | ✅ own bridge + nft table | ❌ | ❌ | ❌ |
| `capabilities.egress: none` | ✅ enforced | ⚠️ label only | ❌ | ❌ |
| `capabilities.devices` | ✅ `--device` | ❌ | ❌ | ❌ |
| `capabilities.interfaces` | ✅ netns move<sup>†</sup> | ❌ | ❌ | ❌ |

<sup>†</sup> Only under `runc`/`crun`, as root, with `ip(8)` and `nsenter(1)`
installed. The runtimes have no flag for this, so the driver moves the network
device into the sandbox's namespace after the container starts. A Kata guest
kernel or a gVisor Sentry never sees the move, because both set up their view of
the network when the sandbox starts, so the capability is reported as false
there instead of being attempted. See
[Hardware and network devices](../guides/enterprise-hosts.md#4-hardware-and-network-devices).

Two entries need explaining:

**Kubernetes cannot build.** A cluster has no builder, unlike a container
runtime with a local image store beside it. Running `setup:` at the start of
each Pod would not be the same: the commands would run again for every task, and
their result would be thrown away with the Pod. So a spec with `setup:` is
refused on Kubernetes, and the error gives the fix: build the steps into an
image, publish it, and reference it as `image:`.

**Kubernetes confines egress with a `NetworkPolicy`, and the cluster has to
enforce it.** For each run, the driver compiles one from the same policy the
container driver's nftables ruleset comes from. It selects only that Pod, by its
unique `cloop.dev/handle-id` label, and the driver creates it before the Pod. On
a cluster whose CNI doesn't implement `NetworkPolicy`, the object has no effect:
flannel accepts it, returns `201`, and enforces nothing. The Kubernetes API has
no way to tell you which kind of cluster you have.

So a project whose `sandbox.yaml` sets `capabilities.egress` is refused on a
Kubernetes executor until you do one of the following:

```bash
# Prove it. Creates two throwaway Pods and a default-deny policy in the
# executor's namespace, checks the connection actually stops working, records
# the verdict, and cleans up on every exit path.
cloop hub doctor --probe-network-policy
```

```yaml
# …or assert it, if you already know your CNI.
executors:
  kubernetes:
    enabled: true
    network_policy_enforced: true
```

`network_policy_enforced` has three states. If you leave it out, a recorded
probe decides. `true` asserts enforcement, but a probe that contradicts it takes
precedence, because the operator may not know the cluster's CNI was replaced.
`false` takes effect immediately, which is how you withdraw the capability after
a CNI change without waiting for a recorded verdict to expire. Verdicts expire
after 30 days and apply to one executor.

`cloop hub doctor` reports the current status without probing, and the
placement error names the command to run. For the full precedence table and how
the probe works, see [Executors →](../architecture/executors.md#does-the-cluster-actually-enforce-a-networkpolicy).

## Reproducibility

`image: python:3.12` names a tag that moves with every patch release, so the
same commit and the same `sandbox.yaml` give a different environment depending
on when they run.

Before starting, the container driver resolves the reference against the local
image store and runs the digest. Each task artifact then records what ran:

```yaml
---
id: 42
title: "Add a retry to the upload path"
status: done
executor_id: "container"
executor_kind: "container"
sandbox_spec_sha256: "9f2c…"
sandbox_image_requested: "ghcr.io/acme/python-toolchain:3.12"
sandbox_image: "ghcr.io/acme/python-toolchain@sha256:1a2b…"
sandbox_reproducible: true
sandbox_setup_sha256: "7d31…"
---
```

`sandbox_spec_sha256` is a hash of the normalized spec, so reformatting the YAML
doesn't change it. `sandbox_setup_sha256` covers only the inputs to the image
build, so editing `env:` doesn't invalidate a built image.

`sandbox_reproducible: false` means the image wasn't pinned by digest. On
Kubernetes the hub normally resolves the tag at the registry before it builds
the Pod (see [Digests, and why a tag is not enough](#digests-and-why-a-tag-is-not-enough)),
so this happens only when a tag couldn't be resolved and went into the Pod as
written. To pin an image everywhere, write the digest into `image:` yourself.

The control plane resolves the digest, but the orchestrator writes the artifacts
from inside the sandbox. The record passes between them through
`.cloop/sandbox-run.json` in the project directory, the only place both can
see.

## Errors

| Situation | HTTP | Error |
| --- | --- | --- |
| Unknown key, bad value, escaping mount | 400 | `sandbox: invalid spec: …`; the author fixes the file |
| Bound executor lacks a capability | 409 | `*executor.PlacementError` naming the constraint |
| Un-isolated executor, or strict mode | 409 | `*executor.HostExecutionDeniedError`, listing isolated executors to bind to |
| `capabilities.network` names a grant the project lacks | 409 | `*sandbox.GrantDeniedError`, with the command to request it |
| `capabilities.network` names a grant the hub cannot serve to this run | 409 | `sandbox_egress_unavailable`: the hub hosts no egress proxy, its proxy didn't bind, or the bound executor has no route to it. The message says which, and how to fix it |
| `capabilities.virtualized` on a kernel-sharing executor | 409 | `*executor.PlacementError`, constraint `virtualization`, or `*executor.HostExecutionDeniedError` when the bound executor is `localprocess` (where the first step is to bind the project to a sandbox anyway) |
| `capabilities.kernel_isolated` on a runc executor | 409 | `*executor.PlacementError`, constraint `kernel_isolation`, naming the config keys for both gVisor and Kata |
| `capabilities.egress: public` on an executor that cannot scope egress | 409 | `*executor.PlacementError`, constraint `egress_scope`. On Kubernetes the message names `cloop hub doctor --probe-network-policy`: the executor can scope egress, but there is no proof yet that the cluster enforces the policy |
| `capabilities.egress: public` on a broker-only executor | 409 | `executor.ErrUnsupported`: the scope asks for more access than the executor gives, so it is refused, not downgraded |
| `capabilities.egress: public` with no `resolvers` configured | 400 | blocking private addresses would also block the sandbox's DNS resolver, so cloop refuses instead of installing a policy without working DNS |
| `capabilities.devices` names an ungranted device | 409 | `*sandbox.DeviceNotGrantedError`, with the `cloop secret grant` command that fixes it |
| `capabilities.interfaces` names an ungranted interface | 409 | `*sandbox.InterfaceNotGrantedError`, with the `cloop secret grant --interfaces` command that fixes it |
| a `host_interface` grant on an executor that cannot move one | 409 | `executor.ErrInvalidSpec`, naming the grant, the binding, and the Kata/gVisor caveat |
| `capabilities.interfaces` together with `network: none` | 400 | `executor.ErrInvalidSpec`: the two settings contradict each other, and following either would drop the other without an error |
| a `host_device` grant on an executor that cannot expose devices | 409 | `executor.ErrInvalidSpec`, naming the grant and the binding |
| `image:` is refused by the trust policy | 409 | `code: sandbox_image_denied`, naming the rule and its remediation |
| the image's `org.cloop.harnesses` label lacks the project's harness | 409 | `code: sandbox_image_lacks_harness`, naming the image, what it carries and an image that carries the harness |
| `image:` is not a usable reference | 400 | `imagepolicy: malformed image reference: …`; the author fixes the file |

Each error carries its own remediation, which the web UI shows separately from
the cause.

---

**See also:** [Executors](../architecture/executors.md) ·
[Secrets and egress](../guides/secrets.md) ·
[Configuration reference](configuration.md) ·
[Security model](../security/model.md)
