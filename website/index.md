# cloop

**Give it a goal. It writes the plan, then works the plan.**

cloop decomposes a goal into a prioritised list of tasks, executes them one at a
time through an AI coding agent, and keeps a durable record of what it did. The
plan is the thing you read, edit and argue with — not a black box you watch
scroll past.

```bash
go install github.com/blechschmidt/cloop@latest

cd ~/src/my-project
cloop init "Add a health check endpoint to the HTTP server"
cloop run
```

That is the whole first run. [Your first project](docs/getting-started/first-project.md)
walks through what happens between those two commands, and what to do when a
task fails.

[Get started](docs/getting-started/installation.md){ .md-button .md-button--primary }
[How it works](docs/getting-started/concepts.md){ .md-button }
[GitHub](https://github.com/blechschmidt/cloop){ .md-button }

---

## Start here

<div class="grid cards" markdown>

-   **[Installation](docs/getting-started/installation.md)**

    Prerequisites, `go install`, building from source, the container image and
    shell completion.

-   **[Your first project](docs/getting-started/first-project.md)**

    One walkthrough: a goal, the plan cloop derives from it, running it,
    watching it, steering it, interrupting it.

-   **[How cloop works](docs/getting-started/concepts.md)**

    The loop itself — what a task is, how one is picked, how completion is
    detected, and what happens when one fails.

-   **[Providers](docs/getting-started/providers.md)**

    Claude Code, the Anthropic API, OpenAI-compatible endpoints, or a local
    Ollama. How provider and model are actually resolved.

</div>

## Run it for a team

The single-user case is one process on your laptop. Everything below is about
relaxing that assumption — a hub other people log into, executing work
somewhere that is not the hub.

The hub never spawns an agent on itself. Work runs in a container, on an
enrolled edge device, or as a Kubernetes Pod, and a bootstrapped configuration
denies host execution and defaults every new user to no role at all.

<div class="grid cards" markdown>

-   **[Executor architecture](docs/architecture/executors.md)**

    How a task travels from the orchestrator to a sandbox and back: the four
    backends, capability-aware placement, health supervision, failover, and
    outbound enrollment for NAT'd edge devices.

-   **[Security model](docs/security/model.md)**

    The four trust boundaries, the no-host-execution guarantee, SSO and RBAC —
    with a table mapping every stated guarantee to the test that checks it.

-   **[Secrets and egress](docs/guides/secrets.md)**

    Grant a GitHub repo, a PAT, a kubeconfig, a registry login or an Internet
    lease to one task, scoped and expiring.

-   **[Operator runbook](docs/operations/runbook.md)**

    Backup and restore, audit-chain verification, key rotation, upgrade,
    rollback, and incident playbooks.

</div>

## Look things up

<div class="grid cards" markdown>

-   **[Commands](docs/reference/commands.md)**

    Every subcommand and flag.

-   **[Configuration](docs/reference/configuration.md)**

    Every `.cloop/config.yaml` key.

-   **[Per-project sandbox](docs/reference/sandbox.md)**

    `.cloop/sandbox.yaml` — the image, setup steps, ceilings and mounts a
    project's tasks run under.

-   **[Documentation map](docs/README.md)**

    The full table of contents, including the threat model and the git
    interception proxy.

</div>

---

## Why the plan is the product

An agent that runs until it decides it is finished gives you one artefact: a
transcript. cloop's is a plan, and that difference is the design.

Every unit of work is a task with an identity, a status and a stored result, so
progress survives a restart, work can be picked up by a different machine than
started it, and a failure names the task it belongs to. When the plan drains,
`--auto-evolve` has the agent propose new work — and that work arrives as
tasks you can read and reject, not as more transcript.

cloop is MIT licensed. Contributions and issues are welcome
[on GitHub](https://github.com/blechschmidt/cloop).
