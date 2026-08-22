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

capabilities:
  git: true       # the sandbox needs a working git
  network: ci     # the name of an egress grant this project already holds

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
| **Network** | Omitting `capabilities.network` forces `--network=none` for the run, whatever the executor is configured with. Naming a grant does *not* turn the network on — it asserts the project already holds that grant, and the executor's own network stands. There is no field that adds egress. |
| **Secrets** | `env` filters an environment the hub already assembled from the project's grants. A name the project was not granted forwards nothing. Values in this file are refused outright (`FOO=bar` is not a valid entry). |
| **Filesystem** | `mounts.source` is relative to the workspace and may not contain `..`, be absolute, or contain a colon (which would append options to the runtime's `-v` flag). Sources are re-checked after symlink resolution, so a symlink inside the repo pointing at `/etc` is rejected too. |
| **Privilege** | Nothing in the schema grants capabilities, changes the UID, or disables seccomp. The generated Dockerfile for `setup:` emits only `FROM`, `LABEL` and `RUN` — no `COPY`, `USER` or `ENV` — so a repo cannot bake its own files or a privileged user into a cached image later tasks inherit. |
| **Build-time network** | A `setup:` build inherits the run's network posture. A spec with no egress grant builds with `--network=none`, so `setup:` is not a way to reach the Internet from a deployment that forbids it. |

An `env:` key that is *absent* means "no opinion" and passes the environment
through untouched. It is not an empty allowlist — reading it that way would
strip the API key from every project that adds a `sandbox.yaml` purely to pin an
image.

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

Two entries deserve their reasons stated plainly:

**Kubernetes cannot build.** There is no builder in a cluster the way there is a
local image store beside a container runtime. Running `setup:` as a Pod prelude
would look equivalent and would not be — the commands would re-run on every task
and their result would be discarded with the Pod. A spec with `setup:` is
therefore refused on Kubernetes, with the remedy: build the steps into an image,
publish it, and reference it as `image:`.

**Kubernetes cannot turn egress off from a Pod spec.** Only a NetworkPolicy can,
and that is a namespace-scoped object the cluster operator owns. The driver
labels every Pod `cloop.dev/egress: deny|allow` so a default-deny policy can
select on it. **Without that policy installed, the label is documentation.**
Install one alongside the hub:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: cloop-sandbox-egress-deny
spec:
  podSelector:
    matchLabels:
      cloop.dev/egress: deny
  policyTypes: [Egress]
  egress: []          # deny all; add a DNS rule if your images need resolution
```

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

Each carries its own remediation, which the Web UI renders as a separate element
from the cause.

---

**See also:** [Executors](../architecture/executors.md) ·
[Secrets and egress](../guides/secrets.md) ·
[Configuration reference](configuration.md) ·
[Security model](../security/model.md)
