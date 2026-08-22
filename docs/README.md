# cloop documentation

Written from the code, and gated against drifting from it. A CI check
(`docs-drift`) fails the build when a new executor backend, a new grantable
secret kind, or a new RBAC role ships without appearing here — see
[`tests/docs/drift_test.go`](../tests/docs/drift_test.go).

## Architecture

- **[Executors](architecture/executors.md)** — how a task travels from the
  orchestrator to a sandbox and back. The `Executor` interface, the four
  backends (`localprocess`, `container`, `remote`, `kubernetes`), registry and
  binding, capability-aware placement, workspace provisioning, health
  supervision, and exactly-once failover. Includes the outbound agent enrollment
  flow for NAT'd edge devices.

## Reference

- **[Per-project sandbox](reference/sandbox.md)** — `.cloop/sandbox.yaml`: the
  repo-committed image, setup steps, environment allowlist, resource ceilings,
  capabilities and mounts one project's tasks run under. What a spec can narrow
  and what it can never widen, which executor honours which field, and the
  digest pin that keeps a run reproducible after the tag moves.

## Security

- **[Security model](security/model.md)** — the four trust boundaries and what
  each authenticates with, the strict no-host-execution guarantee, lease
  revocation, how a workspace credential reaches one process and nothing else,
  roles and permissions, and a table mapping every stated guarantee to the test
  in `tests/security/` that machine-checks it.
- **[Threat model](security/threat-model.md)** — STRIDE per boundary, with the
  concrete mitigation that exists and an honest residual-risk column.

## Guides

- **[Secrets and egress](guides/secrets.md)** — granting a GitHub repo/PAT (for
  a running task, and for the workspace fetch that happens before one), a
  kubeconfig, a registry login, environment variables, and an Internet egress
  lease, with TTLs, constraints, and real command output.

## Operations

- **[Operator runbook](operations/runbook.md)** — backup and restore, database
  maintenance, audit chain verification and SIEM export, key rotation, upgrade,
  rollback, fleet operations, and incident playbooks.

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
