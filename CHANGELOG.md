# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

While the major version is 0, the command-line surface, the configuration
schema and the hub's HTTP API may change in any release.

## [Unreleased]

## [0.0.2] - 2026-09-17

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

[0.0.2]: https://github.com/blechschmidt/cloop/releases/tag/v0.0.2
[0.0.1]: https://github.com/blechschmidt/cloop/releases/tag/v0.0.1
