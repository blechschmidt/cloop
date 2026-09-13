# cloop documentation

Written from the code, and gated against drifting from it. A CI check
(`docs-drift`) fails the build when a new executor backend, a new grantable
secret kind, or a new RBAC role ships without appearing here — see
[`tests/docs/drift_test.go`](../tests/docs/drift_test.go).

New to cloop? Read [your first project](getting-started/first-project.md), then
[how cloop works](getting-started/concepts.md). Everything else on this page
assumes you have run it once.

This file is also the site's table of contents: the published navigation is
generated from the sections and links below, so a page joins the menu the
moment it is listed here and nowhere else.

## Getting started

Five pages in order, indexed at
**[getting started](getting-started/README.md)**:

- **[Installation](getting-started/installation.md)** — prerequisites,
  `go install`, building from source, the container image, shell completion.
- **[Your first project](getting-started/first-project.md)** — one walkthrough:
  a goal, the plan cloop derives from it, running it, watching it, steering it.
- **[How cloop works](getting-started/concepts.md)** — the loop itself: what a
  task is, how one is picked, how completion is detected, what happens on
  failure, and what auto-evolve does once the plan drains.
- **[Providers](getting-started/providers.md)** — the backends, how provider
  and model are actually resolved, and the environment variables that override
  them.
- **[Web dashboard](getting-started/web-ui.md)** — `cloop ui`, what each screen
  shows, and the authentication default to know before exposing it.

## Architecture

- **[Executors](architecture/executors.md)** — how a task travels from the
  orchestrator to a sandbox and back. The `Executor` interface, the four
  backends (`localprocess`, `container`, `remote`, `kubernetes`), registry and
  binding, capability-aware placement, workspace provisioning, health
  supervision, and exactly-once failover. Includes
  [sandbox network isolation](architecture/executors.md#sandbox-network-isolation)
  — the `--internal` network, the host-side nftables ruleset, the per-Pod
  `NetworkPolicy` and why the filter is installed before the workload — and the
  outbound agent enrollment flow for NAT'd edge devices.

## Reference

- **[Per-project sandbox](reference/sandbox.md)** — `.cloop/sandbox.yaml`: the
  repo-committed image, setup steps, environment allowlist, resource ceilings,
  capabilities and mounts one project's tasks run under. What a spec can narrow
  and what it can never widen, which executor honours which field, and the
  digest pin that keeps a run reproducible after the tag moves.
- **[Configuration](reference/configuration.md)** — executors, sandbox images,
  transport security, SSO and TLS, including
  [IP-layer egress filtering](reference/configuration.md#ip-layer-egress-filtering):
  the `egress_filter` keys for both the container and Kubernetes backends, why
  they are off by default, and what a hostname allowlist compiles to at layer 3.
- **[Decision records](reference/adr.md)** — `cloop adr`: recording why the
  system is shaped the way it is, how that differs from the per-task journal,
  and the Proposed → Accepted → Superseded lifecycle, in which a reversal is a
  new record linked to the one it replaces rather than an edit to it.
- **[Commands](reference/commands.md)** — every CLI subcommand, including
  [`cloop egress firewall`](reference/commands.md#cloop-egress-firewall), which
  renders the packet filter an authorisation compiles to and answers
  "would this address get out" with the verdict in its exit status.

## Security

- **[Security model](security/model.md)** — the four trust boundaries and what
  each authenticates with, the strict no-host-execution guarantee, lease
  revocation, how a workspace credential reaches one process and nothing else,
  roles and permissions, and a table mapping every stated guarantee to the test
  in `tests/security/` that machine-checks it. Read
  [the network the sandbox sits on](security/model.md#the-network-the-sandbox-sits-on)
  for what the HTTP proxy binds, what the packet filter binds, and the one thing
  neither can do.
- **[Threat model](security/threat-model.md)** — STRIDE per boundary, with the
  concrete mitigation that exists and an honest residual-risk column, plus the
  [two vulnerabilities found while building the egress filter](security/threat-model.md#vulnerabilities-found-while-building-this).
- **[Git interception proxy](git-interception-proxy.md)** — how a sandbox is
  allowed to push to some branches and not others without ever holding a
  credential that could reach the others: the branch allowlist enforced on the
  push's own ref-update list by a proxy the hub runs, the session model, what a
  leaked token is worth, and [operating it](git-interception-proxy.md#operating-it)
  — `executors.git_proxy`, the certificate the sandbox has to trust, and why
  there is no standalone command. Off by default.

## Guides

- **[Secrets and egress](guides/secrets.md)** — granting a GitHub repo/PAT (for
  a running task, and for the workspace fetch that happens before one), a
  kubeconfig, a registry login, environment variables, and an Internet egress
  lease, with TTLs, constraints, and real command output.
- **[Proving a commit reproduces](guides/reproduce.md)** — `cloop task
  reproduce`: re-running a task in a fresh sandbox and comparing the commit it
  returns against the original. The four verdicts, why equivalence is gated on
  your own test suite rather than an LLM's opinion, how the base commit is
  recovered, and the non-destructive contract.
- **[Kata Containers](guides/kata.md)** — giving a sandbox its own kernel:
  installing Kata, registering it with docker or podman, the `/dev/kvm` and
  nested-virtualization prerequisite, the Kubernetes RuntimeClass path, and how
  to tell whether a workload is really running in a VM.
- **[Critical hosts as executors](guides/enterprise-hosts.md)** — running agent
  tasks on a high-performance machine without letting them reach the rest of the
  estate: per-project repository access, an IP-layer firewall that allows the
  Internet and drops all private address space, a gVisor sandbox whose only view
  of the filesystem is a bind mount, and passing a serial port, GPU or TUN device
  in. Includes the topology table, and what a read-only device grant does and
  does not enforce.

## Operations

- **[Operator runbook](operations/runbook.md)** — backup and restore, database
  maintenance, audit chain verification and SIEM export, key rotation, upgrade,
  rollback, fleet operations, and incident playbooks.
- **[Metrics](operations/metrics.md)** — the `/metrics` endpoint and how to
  authenticate a scraper against it, every exported metric with its labels,
  the alerts worth writing, and what the cardinality ceiling does when an
  instrumentation bug reaches it.

## Elsewhere in the repository

- [`README.md`](../README.md) — overview, install, quick start, command index
- [`deploy/README.md`](../deploy/README.md) — container image, docker-compose
  evaluation stack, Helm chart
- [`tests/security/`](../tests/security/) — the executable specification of the
  threat model

---

### Reading order

Operating a hub: [runbook](operations/runbook.md) → [secrets guide](guides/secrets.md).

Assessing the security posture: [security model](security/model.md) →
[threat model](security/threat-model.md) — the second is only meaningful with
the boundaries from the first.

Extending cloop: [executors](architecture/executors.md) →
[security model](security/model.md#the-no-host-execution-guarantee), because a
new backend must declare its isolation level truthfully; the policy engine
believes it.
