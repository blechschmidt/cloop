# Per-project sandbox: `.cloop/sandbox.yaml`

A hub's `executors.container.image` is one image for every project on it. That
is right on a laptop and wrong for a hub hosting several teams: a repo that
needs a different runtime cannot be executed in isolation at all without an
operator editing the hub's own config, which makes the operator a bottleneck for
a decision that belongs to the repo.

`.cloop/sandbox.yaml` moves that decision into the repository. The operator
keeps the envelope — which executors exist, what they may reach, what the
ceilings are — and the project describes the environment inside it.

- [Schema](#schema)
- [What a spec can and cannot do](#what-a-spec-can-and-cannot-do)
- [`resources.disk` and the workspace](#resourcesdisk-and-the-workspace)
- [Image trust policy](#image-trust-policy)
- [Executor support](#executor-support)
- [Reproducibility](#reproducibility)
- [Errors](#errors)

## Schema

Every key is optional. A missing file, or one containing only comments, means
"use the executor's defaults" — adding cloop to a repo never requires writing
one.

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

# Per-task resource ceilings. Clamped to the hub's limits, not honoured beyond
# them; a clamp is recorded as a warning rather than an error.
resources:
  cpu: 2          # cores; 0 or absent means the executor's default
  memory: 4g      # 512m, 2g, 1024k, or a bare integer read as megabytes
  pids: 512       # process/thread cap
  disk: 2g        # workspace + scratch ceiling; also bounds a fetched tree

capabilities:
  git: true       # the sandbox needs a working git
  network: egress_2f1c9a4e7b3d05286af1c0d4   # the ID of an egress grant this
                  # project holds; `cloop egress list` prints it. Not the
                  # --scope label ("ci", "deps") — that is never matched.
  virtualized: true       # only run behind a hypervisor (Kata); never share a kernel
  kernel_isolated: true   # weaker and usually what you want: gVisor *or* Kata
  egress: public          # public Internet only; drop all private address space
  devices: [serial0]      # select from the host_device grants this project holds

# Re-expose a sub-path of the workspace at another path inside the sandbox.
# Sources are workspace-relative; targets are absolute.
mounts:
  - source: .cache/pip
    target: /home/agent/.cache/pip
  - source: vendor
    target: /opt/vendor
    read_only: true
```

The schema is **closed**: an unknown key is an error, not an ignored line. A
`resource:` that silently parsed as nothing would leave a project running
unbounded while its author believed it was capped.

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

Out-of-range numbers are clamped rather than refused because the author does not
know the hub's ceiling and should not have to; a run that will not start until
someone guesses an acceptable number is worse than one that runs at the limit
and says so. Malformed values are still errors — `2gb` is a typo, not an
ambitious request.

## What a spec can and cannot do

The file arrives by `git pull`. Anyone who can open a pull request can propose
one, and on a hub the person who merges it is not the person whose
infrastructure executes it. Every rule follows from that.

**A spec can narrow. It can never widen.**

| | |
| --- | --- |
| **Network** | Omitting `capabilities.network` forces `--network=none` for the run, whatever the executor is configured with. Naming a grant does *not* turn the network on — it asserts the project already holds the grant with that **ID**, and the executor's own network stands. There is no field that adds egress. The value is compared against `Grant.ID` (the minted `egress_…` string) and never against the `--scope` label, so a human-friendly name here is a denied run, not a matched one. |
| **Secrets** | `env` filters an environment the hub already assembled from the project's grants. A name the project was not granted forwards nothing. Values in this file are refused outright (`FOO=bar` is not a valid entry). |
| **Filesystem** | `mounts.source` is relative to the workspace and may not contain `..`, be absolute, or contain a colon (which would append options to the runtime's `-v` flag). Sources are re-checked after symlink resolution, so a symlink inside the repo pointing at `/etc` is rejected too. |
| **Privilege** | Nothing in the schema grants capabilities, changes the UID, or disables seccomp. The generated Dockerfile for `setup:` emits only `FROM`, `LABEL` and `RUN` — no `COPY`, `USER` or `ENV` — so a repo cannot bake its own files or a privileged user into a cached image later tasks inherit. |
| **Build-time network** | A `setup:` build inherits the run's network posture. A spec with no egress grant builds with `--network=none`, so `setup:` is not a way to reach the Internet from a deployment that forbids it. |
| **Virtualization** | `capabilities.virtualized` is a plain bool, and it does not contradict the rule — it asks for a boundary *stronger* than the executor would otherwise apply, so it needs no grant to name. It cannot turn a runc executor into a Kata one; it can only refuse to run on one. `capabilities.kernel_isolated` is the same shape and weaker: it is satisfied by gVisor as well as Kata, and is what to use unless a hypervisor is specifically required. See [the Kata guide](../guides/kata.md). |
| **Egress scope** | `capabilities.egress` is a closed enum (`public`, `none`), never an address list. Every value removes reach, which is why no grant is needed for any of them — and why there is deliberately no `allow_cidrs` key. Reaching *into* private space is what `capabilities.network` and an operator-issued egress grant are for. `public` is refused, not downgraded, on an executor whose sandboxes only reach an egress broker: there it would be a widening. |
| **Devices** | `capabilities.devices` selects by *name* from the `host_device` grants the project already holds. There is no path-shaped key, for the same reason `mounts.source` cannot be absolute: this file is whatever a pull request says it is, and a device node is an authority over the machine. Naming an ungranted device is a 409, not a silent omission — a missing device node makes the task meaningless. |

An `env:` key that is *absent* means "no opinion" and passes the environment
through untouched. It is not an empty allowlist — reading it that way would
strip the API key from every project that adds a `sandbox.yaml` purely to pin an
image.

### `resources.disk` and the workspace

`disk` is the one resource key that also bounds something the project does not
choose the size of. When an executor has to *fetch* the source tree — a
Kubernetes Pod, a remote agent; anything that does not share the hub's
filesystem — the tree arrives from a remote repository whose contents are known
only after downloading them. So the same number is applied twice:

- as the volume's own ceiling (`ResourceLimits.DiskMB`, which becomes a
  Kubernetes `emptyDir` `sizeLimit`), enforced by the platform;
- as the provisioner's post-fetch check (`Workspace.SizeLimitMB`), which turns
  "this repository is larger than the allowance" into a refusal naming the limit
  rather than a Pod the kubelet evicts mid-run.

What it does **not** do is ask for a workspace. Nothing in this schema names a
repository, and nothing in it adds a workspace placement requirement — a
repo-committed file that could arrange its own clone would be arranging it from
a URL in the same pull request. The workspace *kind* is the hub's decision; a
spec may only bound a fetch the hub already decided to perform.

Executors that share the host filesystem — the container and host-process
drivers — cannot enforce a writable-layer quota, so they refuse a spec that asks
for one rather than accepting a limit they would ignore. Bind-mounted projects
should bound disk on the host filesystem instead.

## Image trust policy

`image:` is the one field the narrowing rules above do not cover, because it is
not a knob on the sandbox — it *is* the sandbox. Its entrypoint, its libraries
and its PATH are the environment the harness runs in, and every credential the
hub injects at start is handed to it. A pull request that chooses the image has
chosen what executes; dropping capabilities around it does not change that.

So the operator constrains which images a project may name, hub-wide, under
`sandbox.image_policy` in `config.yaml`:

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

    # Refuse an image cosign cannot verify. Needs the cosign binary on the hub.
    require_signature: false
    cosign_public_keys:
      - /etc/cloop/cosign/acme.pub
    cosign_identities:
      - issuer: https://token.actions.githubusercontent.com
        subject_regexp: ^https://github\.com/acme/.+

    # Qualify a reference that names no registry. Unset, "alpine:3" is refused.
    default_registry: ""
```

The policy is **deny-by-default within each rule it configures**: with
`allowed_registries` set, a registry not on it is refused. A section that is
absent entirely constrains nothing, which is the single-developer default — a
laptop's `image: python:3.12` keeps working across an upgrade. Rules that are
*present* are the ones that bite, so `require_digest` on its own is a valid
policy meaning "anywhere, but immutably".

The policy governs **project-supplied images only**. `executors.container.image`
and `executors.kubernetes.image` are the operator's own choice, made in the same
file as the policy; running them through an allowlist the same person wrote
would be a lint rather than a control.

### Matching is on the parsed reference

Every comparison is against the reference after it is parsed into
(registry, repository, tag, digest) — never against the string. With
`allowed_registries: [ghcr.io]`, all of these are refused:

| Reference | Actually pulls from | Why a naive check passes it |
| --- | --- | --- |
| `evil.example/ghcr.io/tools` | `evil.example` | the allowed name appears as a repository path |
| `ghcr.io.evil.example/tools` | `ghcr.io.evil.example` | the allowed name appears as a domain prefix |
| `notghcr.io/tools` | `notghcr.io` | the allowed name is a suffix |
| `ghсr.io/tools` | whatever its owner points it at | the `с` is Cyrillic; it renders identically |

The last row is why the whole reference must be ASCII. A valid OCI reference is
ASCII by grammar, so a non-ASCII byte is refused as malformed — which removes
homographs, and the punycode a Unicode-aware normalizer would otherwise produce,
in one rule rather than by enumerating lookalikes.

Similarly, `allowed_repos: [ghcr.io/acme/*]` matches `ghcr.io/acme/tools` and
`ghcr.io/acme/tools/nested`, and does **not** match `ghcr.io/acme-evil/tools`.

### Digests, and why a tag is not enough

`require_digest` refuses `image: ghcr.io/acme/tools:3.12` outright. Where it is
off and a tag is accepted, the container executor resolves it to a digest and
runs *that* — the tag stops existing before anything is inspected, built from or
started, so a tag repointed between the check and the pull cannot change what
runs.

The Kubernetes executor cannot do this. A cluster's image store belongs to its
nodes, so the control plane has nothing to resolve against; the Pod carries the
reference to an API server and some kubelet resolves it later, on a node, when
it schedules. **On Kubernetes, `require_digest: true` is the only thing that
closes that window**, which is why the shipped Helm chart sets it.

An accepted digest reference is reduced to its canonical `repo@sha256:…` form.
A `repo:tag@sha256:…` resolves identically, but then the same artifact would
appear under two spellings in Pod specs, audit rows and artifacts depending only
on how it was written. The requested text is preserved in the task artifact's
`sandbox_image_requested`.

### Signatures

`require_signature` verifies the image with [cosign](https://docs.sigstore.dev/cosign/),
against `cosign_public_keys` (`cosign verify --key`) or `cosign_identities`
(keyless, `--certificate-oidc-issuer` + `--certificate-identity-regexp`). Any
one configured key or identity is enough — listing two describes a rotation or
two trusted publishers, not a quorum.

Two properties are worth stating because their opposites are the usual bugs:

- **Verification is on the digest, never on a tag.** A signature checked against
  a tag verifies whatever the tag pointed at during the check. An image that
  cannot be pinned — a locally built one, with no registry digest — is therefore
  refused under `require_signature` rather than passed.
- **A missing cosign binary is a denial, not a skip.** A hub configured to
  require signatures, on a host with no cosign, refuses every project image with
  an installation diagnostic. The alternative is a hub that reports everything
  as fine while verifying nothing, and the difference is invisible in every
  other observable.

`cosign_identities` requires `subject_regexp`. An issuer alone would trust every
workflow at that provider, including one in a repository you have never heard
of.

Successful verifications are cached per (policy, digest) for an hour, so a
project running one image all day spawns cosign once. A policy edit changes the
cache key; failures are never cached.

### Denials

A refusal names the rule that produced it, and every rule has a remediation
aimed at whoever can act on it:

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

The check runs in three places, and all three apply the same rules:

1. **`.cloop/sandbox.yaml` validation** — so a bad image is a config error
   surfaced in the UI before a run starts, not a container that fails to launch.
2. **The container executor**, before the image is pulled, inspected or run.
3. **The Kubernetes pod builder**, before the reference becomes a field the API
   server accepts.

The executors are the authority — they are what runs the image — and the
validation pass exists so the error arrives early and reads as a file problem.

Every denial is written to the audit trail as `sandbox.image_denied`, carrying
the project, the reference *as written* (not normalized — that would hide the
homograph that is the reason to look), the rule and the parsed registry and
repository. The question it is there to answer is not "did this one repo have a
typo" but "did the same unknown registry get named across six projects in an
hour".

## Executor support

A spec is matched against the executor's advertised capabilities *before* the
run starts, using the same matcher the scheduler uses
([`pkg/executor/placement.go`](../../pkg/executor/placement.go)). A spec asking
for something the executor cannot do is refused with the constraint named — it
is never partially applied.

| | `container` | `kubernetes` | `remote` | `localprocess` |
| --- | --- | --- | --- | --- |
| `image` | ✅ | ✅ | ❌ | ❌ |
| `setup` | ✅ | ❌ | ❌ | ❌ |
| `mounts` | ✅ (bind) | ✅ (`subPath`) | ❌ | ❌ |
| `resources` | ✅ | ✅ (no `pids`) | ❌ | ❌ |
| `capabilities.network` off | ✅ enforced | ⚠️ label only | ❌ | ❌ |
| `capabilities.virtualized` | ✅ with `oci_runtime` | ✅ with `runtime_class` | ❌ | ❌ |
| `capabilities.kernel_isolated` | ✅ with `oci_runtime` (`runsc` or kata) | ✅ with `runtime_class` | ❌ | ❌ |
| `capabilities.egress: public` | ✅ own bridge + nft table | ❌ | ❌ | ❌ |
| `capabilities.egress: none` | ✅ enforced | ⚠️ label only | ❌ | ❌ |
| `capabilities.devices` | ✅ `--device` | ❌ | ❌ | ❌ |

Two entries deserve their reasons stated plainly:

**Kubernetes cannot build.** There is no builder in a cluster the way there is a
local image store beside a container runtime. Running `setup:` as a Pod prelude
would look equivalent and would not be — the commands would re-run on every task
and their result would be discarded with the Pod. A spec with `setup:` is
therefore refused on Kubernetes, with the remedy: build the steps into an image,
publish it, and reference it as `image:`.

**Kubernetes confines egress with a `NetworkPolicy`, and the cluster has to
apply it.** The driver compiles one per run from the same policy the container
driver's nftables ruleset is compiled from, selecting that Pod alone by its
unique `cloop.dev/handle-id` label, and creates it before the Pod it governs.
That object is inert on a cluster whose CNI does not implement `NetworkPolicy` —
flannel accepts it, returns `201`, and enforces nothing — and the Kubernetes API
cannot be asked which case you are in.

So a project whose `sandbox.yaml` sets `capabilities.egress` is **refused** on a
Kubernetes executor until one of these is true:

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

`network_policy_enforced` is a three-state field. Leaving it out defers to a
recorded probe. `true` asserts enforcement — a probe that *contradicts* it wins,
because an operator can be wrong about a cluster whose CNI was swapped under
them. `false` is a veto that takes effect immediately, which is how you withdraw
the capability after a CNI change without waiting for a recorded verdict to
expire. Verdicts expire after 30 days and are scoped to one executor.

`cloop hub doctor` reports the current status without probing, and the placement
refusal names the command to run. For the full precedence table and the design
of the probe, see [Executors →](../architecture/executors.md#does-the-cluster-actually-enforce-a-networkpolicy).

## Reproducibility

`image: python:3.12` names a moving target: the tag is repointed on every patch
release, so the same commit and the same `sandbox.yaml` produce a different
environment depending on when they ran.

The container driver resolves the reference against the local image store before
starting, and runs the **digest**. Each task artifact then records what actually
executed:

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

`sandbox_spec_sha256` hashes the *normalized* spec, so reformatting the YAML
does not change it, and `sandbox_setup_sha256` covers only the image-build
inputs — editing `env:` does not invalidate a built image.

`sandbox_reproducible: false` means the image was not digest-pinned. On
Kubernetes that is the normal case, because the control plane has no local store
to resolve against; pin it yourself by writing the digest into `image:`.

The record travels from the control plane (which resolved the digest) to the
orchestrator (which writes artifacts, from *inside* the sandbox) through
`.cloop/sandbox-run.json` in the project directory — the only thing both sides
can see.

## Errors

| Situation | HTTP | Error |
| --- | --- | --- |
| Unknown key, bad value, escaping mount | 400 | `sandbox: invalid spec: …` — the author fixes the file |
| Bound executor lacks a capability | 409 | `*executor.PlacementError` naming the constraint |
| Un-isolated executor, or strict mode | 409 | `*executor.HostExecutionDeniedError`, listing isolated executors to bind to |
| `capabilities.network` names a grant the project lacks | 409 | `*sandbox.GrantDeniedError`, with the command to request it |
| `capabilities.virtualized` on a kernel-sharing executor | 409 | `*executor.PlacementError`, constraint `virtualization` — or `*executor.HostExecutionDeniedError` when the bound executor is `localprocess`, where binding to a sandbox is the first step anyway |
| `capabilities.kernel_isolated` on a runc executor | 409 | `*executor.PlacementError`, constraint `kernel_isolation`, naming both the gVisor and the Kata config key |
| `capabilities.egress: public` on an executor that cannot scope egress | 409 | `*executor.PlacementError`, constraint `egress_scope`. On Kubernetes the message names `cloop hub doctor --probe-network-policy`, because the executor *can* scope egress — what is missing is proof the cluster applies the policy |
| `capabilities.egress: public` on a broker-only executor | 409 | `executor.ErrUnsupported` — the scope asks for more reach than the executor grants, so it is refused rather than downgraded |
| `capabilities.egress: public` with no `resolvers` configured | 400 | dropping private space drops the sandbox's resolver, so cloop refuses rather than install a policy with no working DNS |
| `capabilities.devices` names an ungranted device | 409 | `*sandbox.DeviceNotGrantedError`, with the `cloop secret grant` command that fixes it |
| a `host_device` grant on an executor that cannot expose devices | 409 | `executor.ErrInvalidSpec`, naming the grant and the binding |
| `image:` is refused by the trust policy | 409 | `code: sandbox_image_denied`, naming the rule and its remediation |
| `image:` is not a usable reference | 400 | `imagepolicy: malformed image reference: …` — the author fixes the file |

Each carries its own remediation, which the Web UI renders as a separate element
from the cause.

---

**See also:** [Executors](../architecture/executors.md) ·
[Secrets and egress](../guides/secrets.md) ·
[Configuration reference](configuration.md) ·
[Security model](../security/model.md)
