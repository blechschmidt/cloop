# cloop documentation

Written from the code, and gated against drifting from it. A CI check
(`docs-drift`) fails the build when a new executor backend, a new grantable
secret kind, or a new RBAC role ships without appearing here — see
[`tests/docs/drift_test.go`](../tests/docs/drift_test.go).

## Architecture

- **[Executors](architecture/executors.md)** — how a task travels from the
  orchestrator to a sandbox and back. The `Executor` interface, the four
  backends (`localprocess`, `container`, `remote`, `kubernetes`), registry and
  binding, capability-aware placement, health supervision, and exactly-once
  failover. Includes the outbound agent enrollment flow for NAT'd edge devices.

## Security

- **[Security model](security/model.md)** — the four trust boundaries and what
  each authenticates with, the strict no-host-execution guarantee, roles and
  permissions, and a table mapping every stated guarantee to the test in
  `tests/security/` that machine-checks it.
- **[Threat model](security/threat-model.md)** — STRIDE per boundary, with the
  concrete mitigation that exists and an honest residual-risk column.

## Guides

- **[Secrets and egress](guides/secrets.md)** — granting a GitHub repo/PAT, a
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
