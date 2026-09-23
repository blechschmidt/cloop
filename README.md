# cloop

[![CI](https://github.com/blechschmidt/cloop/actions/workflows/ci.yml/badge.svg)](https://github.com/blechschmidt/cloop/actions/workflows/ci.yml)
[![Docs](https://github.com/blechschmidt/cloop/actions/workflows/docs.yml/badge.svg)](https://blechschmidt.github.io/cloop/)

**Give it a goal. It writes the plan, then works the plan.**

cloop decomposes a goal into a prioritised list of tasks, executes them one at a
time through an AI coding agent, and keeps a durable record of what it did. The
plan is the thing you read, edit and argue with — not a black box you watch
scroll past.

📖 **[Documentation](https://blechschmidt.github.io/cloop/)** ·
[Getting started](https://blechschmidt.github.io/cloop/docs/getting-started/installation/) ·
[How it works](https://blechschmidt.github.io/cloop/docs/getting-started/concepts/)

## Quick start

```bash
go install github.com/blechschmidt/cloop@latest

cd ~/src/my-project
cloop init "Add a health check endpoint to the HTTP server"
cloop run
```

No Go toolchain? Grab a static binary for Linux or macOS from the
[latest release](https://github.com/blechschmidt/cloop/releases/latest) —
see [Installation](https://blechschmidt.github.io/cloop/docs/getting-started/installation/)
for the checksum-verifying one-liner.

That is the whole first run. cloop calls your provider once to turn the goal
into a numbered plan, then works through it — writing code, running your
tests, and recording the result of each task before it starts the next one.

```bash
cloop status     # the goal, the provider, and where the plan stands
cloop log        # what it has done, step by step
cloop ui         # the same thing in a browser, live
```

[**Your first project**](docs/getting-started/first-project.md) walks through
what happens between those commands, and what to do when a task fails.
[**A walkthrough of the dashboard**](docs/getting-started/walkthrough.md) does
the same ground in a browser, in screenshots: where work is allowed to run, a
project pinned there, and the plan it runs.

### Requirements

- **Go 1.25+** to build it (`go.mod` pins the toolchain).
- **A provider.** The default is the [Claude Code](https://claude.com/claude-code)
  CLI, which needs `claude` on your `PATH` and a logged-in session. The
  Anthropic, OpenAI and Ollama backends need only an API key — or nothing at
  all, in Ollama's case.

Building from source instead:

```bash
git clone https://github.com/blechschmidt/cloop.git
cd cloop && go build -o cloop .
```

## Why the plan is the product

An agent that runs until it decides it is finished gives you one artefact: a
transcript. cloop's is a plan, and that difference is the design.

Every unit of work is a task with an identity, a status and a stored result. So
progress survives a restart, a task can be picked up by a different machine than
started it, and a failure names the task it belongs to instead of scrolling
past. When a task fails, cloop retries it with a mutated prompt before giving
up, and stops the run after three consecutive failures rather than thrashing.

When the plan drains, `--auto-evolve` has the agent propose new work — and that
work arrives as tasks you can read and reject, not as more transcript.

![Task management](docs/screenshots/03-tasks.png)

## Providers

Switch with `--provider`, or set a default with `cloop config set provider <name>`.

| Provider | What it is | Auth |
| --- | --- | --- |
| `claudecode` | the Claude Code CLI (default) | an existing `claude` login |
| `anthropic` | the Anthropic API directly | `ANTHROPIC_API_KEY` |
| `openai` | Chat Completions, including OpenAI-compatible endpoints | `OPENAI_API_KEY` |
| `ollama` | a local Ollama server — no key, no cost | none |

`cloop providers --test` checks what is configured and whether it answers.
There is also a `mock` provider for tests and CI, which never calls the network.

See [choosing and configuring a provider](docs/getting-started/providers.md)
for how provider and model are actually resolved, and which environment
variables override which.

## Documentation

The full documentation is published at
**[blechschmidt.github.io/cloop](https://blechschmidt.github.io/cloop/)**, and
its source is [`docs/`](docs/README.md).

| | |
| --- | --- |
| **[Getting started](docs/getting-started/README.md)** | install, your first project, how the loop works, providers, the dashboard, and a screenshot walkthrough of it |
| **[Executor architecture](docs/architecture/executors.md)** | how a task travels from the orchestrator to a sandbox and back — the four backends, placement, health supervision, failover, remote agent enrollment |
| **[Security model](docs/security/model.md)** | the four trust boundaries, the no-host-execution guarantee, SSO and RBAC, and a table mapping every guarantee to the test that checks it |
| **[Threat model](docs/security/threat-model.md)** | STRIDE per boundary, with an honest residual-risk column |
| **[Secrets and egress](docs/guides/secrets.md)** | granting a GitHub repo/PAT, kubeconfig, registry login or Internet lease, with TTLs and constraints |
| **[Git interception proxy](docs/git-interception-proxy.md)** | letting a sandbox push to some branches and not others without handing it a credential that could reach the rest |
| **[Kata Containers](docs/guides/kata.md)** | giving a sandbox its own kernel |
| **[Operator runbook](docs/operations/runbook.md)** | backup and restore, audit verification, key rotation, upgrade, rollback, incident playbooks |
| **[Command reference](docs/reference/commands.md)** | every command and flag |
| **[Configuration reference](docs/reference/configuration.md)** | every `.cloop/config.yaml` key |
| **[Per-project sandbox](docs/reference/sandbox.md)** | `.cloop/sandbox.yaml` — the image, setup steps, ceilings and mounts a project's tasks run under |
| **[Deployment](deploy/README.md)** | container image, docker-compose evaluation stack, Helm chart |

`cloop <command> --help` covers anything not written up.

## Running it for a team

Everything above is one process on one machine. cloop also runs as a
multi-user hub with SSO, RBAC, brokered credentials and isolated executors.
The hub itself never spawns an agent: work runs in a container, on an enrolled
edge device, or as a Kubernetes Pod.

```bash
cloop hub bootstrap --external-url https://cloop.example.com \
  --oidc-issuer https://idp.example.com --oidc-client-id cloop-hub
```

That writes a configuration with `executors.allow_host_process: false` and
`default_role: none` — no host execution, deny by default. From there, read the
[security model](docs/security/model.md), then the
[operator runbook](docs/operations/runbook.md).

### Security conformance suite

[`tests/security/`](tests/security/) is an executable specification of the
threat model. Every check asserts a property whose absence is **invisible at
runtime**: the feature still works, the logs look normal, and only an attacker
notices the difference.

```bash
go test -race ./tests/security/
```

It runs as a required CI job. Each guarantee is mapped to the test that checks
it in the [security model](docs/security/model.md#the-guarantee--test-table).

## Development

```bash
make build          # compile ./cloop
make test           # unit tests (race + coverage) and the e2e suite
make docs-serve     # live-preview the documentation site
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full workflow, and the
[Makefile](Makefile) for fuzzing and the docker-compose evaluation stack.

## License

MIT
