# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

While the major version is 0, the command-line surface, the configuration
schema and the hub's HTTP API may change in any release.

## [Unreleased]

### Added

- **Virtual executors.** An enrolled device can carry named sub-executors, each
  with its own container engine, OCI runtime and image, an **IP firewall with an
  allowlist and a denylist**, and the **host devices** its sandboxes are given.
  Projects bind to one like to any executor, and resource limits and the access
  list apply to it under its own ID — so one machine can offer a locked-down
  sandbox to everyone and one holding its hardware security module to the few
  people allowed near it. Press **Virtual** on a device's card in the Executors
  tab: the dialog shows the device's USB devices (vendor, product, serial, node;
  **Refresh** re-reads them from the device) to pick from. The Settings tab lists
  every enrolled device's USB hardware, each with a way into that dialog. API:
  `/api/executors/{device}/virtuals` and `/api/executors/{id}/virtual`; audit
  action `executor.virtual`. See `docs/guides/virtual-executors.md`.
- **Executor protocol v14.** Agents report their USB inventory (read from sysfs,
  which the hardened unit leaves visible), whether they can install a packet
  filter, and their engine's OCI runtimes; a start frame can carry a virtual
  executor's firewall and devices, which the device resolves against its live
  hardware at every dispatch — an unplugged device fails the start, naming it.
  A USB device is selected by identity rather than by `/dev/bus/usb` path, which
  changes on every re-enumeration.
- `cloop executor agent install --packet-filter` grants the agent
  `CAP_NET_ADMIN` and netlink so it can install a virtual executor's firewall
  with nft(8); without it such a virtual executor is refused, never started
  unfiltered.
- A denylist for the IP-layer egress filter (`netfilter.Input.DenyCIDRs`),
  compiled ahead of every allow and carried into Kubernetes NetworkPolicies as
  `except` ranges.

### Fixed

- A project's `capabilities.egress: public` on an executor whose firewall allows
  only a private range handed the project the whole public Internet. It is now
  refused, like the broker-only case: a scope may only remove reach.
- Device passthrough is no longer advertised or attempted under gVisor or Kata.
  Measured on a gVisor host: the node exists in the sandbox and every open of it
  fails with `ENXIO`. The enterprise-hosts guide claimed the combination worked.
- A filtered sandbox resolves through the resolvers its filter opened, named in
  a `resolv.conf` of its own. Dropping private space also drops the engine's
  default resolver — on a cloud VM usually the provider's, in CGNAT space — and
  under gVisor Docker's embedded resolver on `127.0.0.11` is unreachable
  altogether (measured: every lookup `EAI_AGAIN`), so DNS failed inside such a
  sandbox.
- An egress filter is refused under rootless podman, whose networks live in a
  network namespace the host's packet filter cannot see: the ruleset loaded,
  matched nothing, and the sandbox ran unfiltered.
- A task whose harness reported "API Error: Can't reach the API server" was
  recorded as done. An unreachable provider is now an abort
  (`network_unreachable`) that pauses the run and names the cause.
- Revoking a device deletes its virtual executors, each with an audit row.
- The Executors panel's sandbox chip always described a container-mode device's
  network as `none`: the card read a field the API never filled in.

## [0.0.4] - 2026-09-27

The first release that ships 0.0.2's installer fix. 0.0.2 was tagged on
2026-09-17 to publish unversioned asset names and never reached GitHub
Releases: its publish step failed partway through the uploads, the tag stayed
behind with no release, and `releases/latest/download` kept serving 0.0.1's
versioned names — so every device the installer was pointed at still got a
`404`. 0.0.3, tagged to publish it, stopped earlier still: its binaries did not
build for 32-bit linux/arm. What 0.0.2 was cut for is released here for the
first time: unversioned `cloop_<os>_<arch>.tar.gz` assets that
`latest/download` resolves, each with the Sigstore bundle the installer and
`cloop upgrade` verify its provenance against (0.0.1 published none), linux/arm
builds, and a daily check that the published release still installs — see 0.0.2
in `CHANGELOG.md` for the detail.

### Added

- **Parallel features.** `cloop feature new` — and **+ New feature** on a
  project's Overview — starts a line of work in its own git worktree on branch
  `cloop/feature/<slug>`, with its own task list and its own auto-evolve,
  innovate and parallel settings. Features run at the same time as their project
  and as each other; the dashboard nests them under their project, and each is
  otherwise an ordinary project with its own run, tasks and options. When one is
  done, **Open pull request** (`cloop feature pr`) pushes its branch and opens a
  GitHub pull request into the branch it was cut from — or the hub does it by
  itself on completion when the feature asked for that. A feature runs on its
  project's executor with its project's grants and roles, by a mapping read from
  its path so that it fails closed. See `docs/guides/features.md`.

### Changed

- **The dashboard's script ships without its comments.** Whole-line `//`
  comments were over a third of its wire bytes; they are now stripped when the
  bundle is built, keeping every line number, by a lexer that refuses — and
  serves the source unchanged — whenever it cannot prove a line is a comment.
  First paint fell from 279 KB to 213 KB, the parallel-features UI included.
- **Stop, the running indicator and run re-entrancy treat a feature as its own
  project.** A run in `.cloop/features/<slug>` no longer marks its parent as
  running, and the parent's Stop no longer signals it.
- `cloop clean` refuses while the project has features unless `--force`, which
  removes them through git first; snapshots neither archive feature worktrees
  nor touch them on restore; disk-usage reports no longer count them.
- **`cloop watch` applies one batch of changes at a time.** Every debounce
  window used to start a batch of its own, so a burst of edits applied several
  at once: their state saves raced — one could put back a task another had just
  reset — `--auto-run` ran `cloop run --pm` concurrently with itself, and
  stopping the watcher waited for the whole backlog. Changes that arrive while
  a batch is applied now make up the next one, and nothing starts after Ctrl+C.

### Fixed

- **cloop builds for 32-bit ARM again.** A token ceiling of `1<<40` did not fit
  in an `int` on linux/arm, the armv7 build the installer serves to Raspberry
  Pi-class devices, so nothing since 2026-09-26 compiled there. CI now builds
  the release binary for every published platform on every push, so a tag is no
  longer the first build to try one.
- **A release publishes, or can be resumed.** The release job now creates the
  release as a draft, uploads one asset at a time with retries, and marks it
  latest only once every asset is there. 0.0.2 was lost to a single upload
  error from GitHub with all twelve uploads running at once.
- **A terminal on an edge device no longer loses a short command's output.**
  A command that printed and exited at once — `pwd`, `echo` — sent its output
  and its close back to back, and the hub closed the session before relaying
  the output, so `cloop task attach` showed an empty transcript. The device
  also reaped such a command twice, a data race, and could hold one of its
  terminal slots for a session that had already ended; an attach the device
  refused left a goroutine behind on the hub.
- **A workload stopped on reconnect reports how it ended.** When the control
  plane refuses to take a workload back after a reconnect, the device stops it
  — but it used to signal it before the new session was ready, so a workload
  that died promptly had nowhere to send its last output or its exit status.
- **An exit reported as the link drops is kept.** The device counted a
  workload's final status as delivered before writing it, so a status written
  to a closing session was lost, and the control plane later read a clean exit
  as a lost workload. It is now delivered on the next session.
- **A revocation is sent to a reconnecting device once.** One recorded as the
  device reconnected could be sent twice, and the reply to the first could be
  taken by the second, reporting a reachable device as unreachable.
- **Push-to-talk no longer sends a clip it meant to discard.** A tap too short
  to be speech is thrown away, but its recorder stopped asynchronously, and a
  press landing before it had — a second tap at once, or any press on a slow
  device — let the discarded clip upload after all, often transcribed as a
  hallucinated title. A release the page got to late could also stretch a tap
  past the minimum hold. Holds are now timed by the pointer events themselves,
  on the dashboard and the glasses link alike.
- **`cloop chaos suite` gives every fault its full window.** Windows were
  measured from when the suite was built, so the last faults ran with a
  fraction of theirs — the SQLite one with under half a second of its two —
  and a slow disk reported them degraded.

### Security

- **gRPC 1.83.2** for GO-2026-6348, heap exhaustion through fragmented HTTP/2
  DATA frames, which the hub's metrics collectors can reach. OpenTelemetry
  moves to 1.44.0 with it.

## [0.0.3] - 2026-09-27

_Tagged, never published as a binary release: the release build failed on
linux/arm before anything was uploaded. Its container images were published
(`ghcr.io/blechschmidt/cloop` and `cloop-harness` at `v0.0.3`). Its changes
were released in 0.0.4._

## [0.0.2] - 2026-09-17

_Tagged, never published: the release job failed while uploading. Its changes
were released in 0.0.4._

This release exists to publish the installer fix below, which was written
against 0.0.1 and then never shipped. The repository was corrected; no release
was cut; and so `releases/latest/download` kept resolving against the versioned
names 0.0.1 had published, and every device kept getting a `404`. The code
being right is not the same as the artifact being right — and from a device,
only the artifact is reachable.

### Added

- **A scheduled check that the published release still installs.** Every
  existing gate compares this repository against itself, which is why the
  0.0.1 breakage survived its own fix: `scripts/build-release.sh`,
  `pkg/upgrade.assetNameFor` and the generated script all agreed, and the
  release disagreed with all three. `.github/workflows/released-installer.yml`
  now runs the real installer against the real release on a timer, because a
  release that goes stale relative to the code produces no commit for a
  pull-request check to catch.

### Fixed

- **The executor bootstrap installer could never install anything.** Two
  defects on the same path, the first hiding the second. Release archives
  carried the version in their names (`cloop_0.0.1_linux_amd64.tar.gz`) while
  the script served at `GET /install.sh` fetched
  `releases/latest/download/cloop_linux_amd64.tar.gz` — a URL no release had
  ever published, so every device got a `404`. With that fixed the install
  still died at exit 127: progress messages went to stdout, which is the
  channel `find_or_fetch_cloop` returns the binary path on, so the path came
  back with a log line glued to the front of it and was executed as one word.
  Release assets are now unversioned — which is what makes `latest/download`
  resolve at all — and every diagnostic goes to stderr.

### Added

- **The installer verifies what it downloads.** The archive is checked against
  the release's `checksums.txt` before anything is unpacked, failing closed on
  a mismatch, an unreachable checksums file, or an artifact missing from it.
  It is unpacked as root onto a device about to be handed credentials, so
  authenticating only the transport was not enough. `CLOOP_BIN` still bypasses
  the download entirely.
- **`linux/arm` (armv7) release builds.** The installer already mapped
  `armv7l`/`armv7`/`armhf` onto an asset that was never built, so 32-bit
  Raspberry Pi-class devices — the fleet's most likely edge hardware — were
  told "download failed".

### Changed

- Release assets are named `cloop_<os>_<arch>.tar.gz` rather than
  `cloop_<version>_<os>_<arch>.tar.gz`. `cloop upgrade` reads both, so a
  v0.0.1 binary still upgrades forward; the version now lives in the binary
  (`cloop version`) instead of in the filename.

## [0.0.1] - 2026-09-12

First tagged release. Everything below already existed; what is new is that it
is now installable as a versioned binary rather than only from source.

### Added

- **Autonomous task loop.** `cloop init` turns a goal into a plan and
  `cloop run` executes it: decompose into tasks, run each against an AI
  provider, detect completion from the agent's own output, and — with
  `--auto-evolve` — discover follow-up work and keep going.
- **Multiple providers.** Anthropic, OpenAI (including OpenAI-compatible
  endpoints), Ollama for local models, and the Claude Code CLI. Selection is
  layered: `--provider` flag, then `.cloop/config.yaml`, then project state.
  Retries use exponential backoff with jitter behind a circuit breaker.
- **Isolated executors.** The hub never spawns a harness on the host unless
  explicitly configured to. Backends: local process, Docker/Podman containers,
  Kubernetes pods, Kata Containers VMs, and remote agents that enrol
  themselves outbound — so an edge device behind NAT needs no inbound
  reachability. Placement is capability-aware with liveness, cordon/drain and
  automatic failover.
- **Scoped secret brokering.** GitHub repositories and PATs, kubeconfigs, and
  the hub's own Internet connection are leased to executors with a TTL rather
  than copied in. Leases are revoked on the running executor rather than at
  task exit, payloads are envelope-encrypted with online key rotation, and
  material is wiped on exit and swept at startup.
- **Enterprise hub.** OIDC authentication with claim-based RBAC that is
  deny-by-default on every mutating endpoint, durable sessions with idle
  timeout and admin revocation, scoped API tokens for non-interactive access,
  per-identity quotas and admission control, a hash-chained audit trail with
  SIEM export, and a container image trust policy (registry allowlist, digest
  pinning, signature verification).
- **Web dashboard.** Multi-project oversight over a WebSocket event stream,
  with kanban, dependency graph, timeline, analytics, knowledge base, and
  panels for executors, secrets, grants and audit.
- **Packaging.** A distroless container image, a docker-compose evaluation
  stack that runs a real task through a remote executor, a Helm chart, and
  `cloop hub bootstrap` / `cloop hub doctor`.
- **Roughly 115 CLI commands** covering planning, analysis, forecasting,
  reporting and integration. `cloop --help` groups them; `cloop doctor`
  checks the environment.

### Known limitations

- **No Windows build.** The process-group supervision used to stop harnesses
  is POSIX-only, so releases carry linux and darwin binaries (amd64 and arm64)
  only. `cloop upgrade` already knows how to unpack a `cloop.exe`; the
  platform needs a port, not a packaging change.
- The version is `0.0.1` in the sense SemVer intends: interfaces are not yet
  stable, and upgrades between 0.0.x releases may require configuration
  changes.

[0.0.4]: https://github.com/blechschmidt/cloop/releases/tag/v0.0.4
[0.0.3]: https://github.com/blechschmidt/cloop/tree/v0.0.3
[0.0.2]: https://github.com/blechschmidt/cloop/tree/v0.0.2
[0.0.1]: https://github.com/blechschmidt/cloop/releases/tag/v0.0.1
