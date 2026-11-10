# cloop

**cloop is a Software Factory: it builds software for you with AI coding agents.**

You tell cloop what you want: a one-line goal, a list of tasks, or a written
specification. cloop splits the work into tasks and hands them, one after
another, to a coding agent such as Claude Code, which writes the code in your
repository and runs your tests. cloop keeps track of every task and its
outcome, retries what fails, and keeps going until the job is done.

```bash
go install github.com/blechschmidt/cloop@latest

cd ~/src/my-project
cloop init "Add a health check endpoint to the HTTP server"
cloop run
```

`cloop init` saves the goal, and `cloop run` turns it into a short list of
tasks and works through them. [Your first project](docs/getting-started/first-project.md)
shows what happens during those two commands, and what to do when a task fails.

[Get started](docs/getting-started/installation.md){ .md-button .md-button--primary }
[How it works](docs/getting-started/concepts.md){ .md-button }
[GitHub](https://github.com/blechschmidt/cloop){ .md-button }

---

## Start here

<div class="grid cards" markdown>

-   **[Installation](docs/getting-started/installation.md)**

    What you need, `go install`, building from source, the container image and
    shell completion.

-   **[Your first project](docs/getting-started/first-project.md)**

    A complete first run: a goal, the plan cloop makes from it, running the
    plan, watching it, changing it and stopping it.

-   **[How cloop works](docs/getting-started/concepts.md)**

    What a task is, how cloop picks the next one, how it knows a task is
    finished, and what happens when one fails.

-   **[Providers](docs/getting-started/providers.md)**

    Claude Code, the GitHub Copilot CLI, the Anthropic API, OpenAI-compatible
    endpoints or a local Ollama, and how cloop decides which provider and model
    to use.

</div>

## Run it for a team

On your own machine cloop is a single process. For a team it runs as a hub:
a server that people sign in to with single sign-on, which runs the work
somewhere other than on itself.

The hub never starts an agent on its own host. Tasks run in containers, on
machines you enroll as executors, or as Kubernetes Pods. A hub set up with
`cloop hub bootstrap` refuses to run anything on its own host, and gives new
users no access until an administrator assigns them a role.

**[Component and security architecture](docs/architecture/README.md)** gives
an overview of the whole system and links to everything below.

<div class="grid cards" markdown>

-   **[Executor architecture](docs/architecture/executors.md)**

    How a task gets from the hub to a sandbox and back: the four backends, how
    a machine is chosen, health checks, failover, and enrolling machines behind
    NAT.

-   **[Security model](docs/security/model.md)**

    The trust boundaries, why work never runs on the hub's host, sign-in and
    roles, and which test checks each guarantee.

-   **[Secrets and egress](docs/guides/secrets.md)**

    Give one task access to a GitHub repository, a token, a kubeconfig, a
    registry login or the Internet, with limits and an expiry.

-   **[Operator runbook](docs/operations/runbook.md)**

    Backups and restores, checking the audit trail, key rotation, upgrades,
    rollbacks, and what to do in an incident.

</div>

## Look things up

<div class="grid cards" markdown>

-   **[Commands](docs/reference/commands.md)**

    Every command and flag.

-   **[Configuration](docs/reference/configuration.md)**

    Every `.cloop/config.yaml` key.

-   **[Per-project sandbox](docs/reference/sandbox.md)**

    `.cloop/sandbox.yaml`: the image, setup steps, resource limits and mounts
    for a project's tasks.

-   **[Documentation map](docs/README.md)**

    The full table of contents, including the threat model and the git
    interception proxy.

</div>

---

## What you get from a run

Every piece of work is a task with a number, a status and a saved result, so
you can always see what cloop did and why. Progress survives a restart, a task
can be continued on a different machine from the one that started it, and when
something fails you know which task it was. With `--auto-evolve`, cloop
suggests new tasks once the plan is finished. They are added to the plan like
any other task, so you can read, edit or delete them.

cloop is MIT licensed. Contributions and issues are welcome
[on GitHub](https://github.com/blechschmidt/cloop).
