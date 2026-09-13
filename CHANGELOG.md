# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

While the major version is 0, the command-line surface, the configuration
schema and the hub's HTTP API may change in any release.

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

[0.0.1]: https://github.com/blechschmidt/cloop/releases/tag/v0.0.1
