# Your first project

One walkthrough, start to finish: a directory, a goal, a task plan, and a run
you can watch, steer and interrupt.

The shape to hold in your head is that **cloop never executes a goal directly.**
It decomposes the goal into a numbered plan of tasks, saves that plan, and then
works through it one task at a time. The plan is the thing you review, edit and
argue with; the run is just what happens to it.

- [Setting a goal](#setting-a-goal)
- [What `.cloop/` now holds](#what-cloop-now-holds)
- [The first run](#the-first-run)
- [Watching it](#watching-it)
- [Steering the plan](#steering-the-plan)
- [Stopping and resuming](#stopping-and-resuming)

---

## Setting a goal

Work inside the repository you want changed. cloop edits the directory it is
run from, so a scratch clone is a reasonable place to start.

```console
$ cd ~/src/demo-api
$ cloop init "Add a health check endpoint to the HTTP server"
✓ cloop initialized
  Goal: Add a health check endpoint to the HTTP server
  Max steps: 0
  State: /home/you/src/demo-api/.cloop/state.json
  Config: /home/you/src/demo-api/.cloop/config.yaml
  Provider: claudecode (default)

Run 'cloop run' to start.
Run 'cloop run' to decompose your goal into tasks and execute them.
```

A goal is a sentence, not a prompt. It is stored once and every task prompt is
derived from it, so vagueness here is amplified across every task in the plan.

The flags worth knowing on the first project:

| Flag | Does |
| --- | --- |
| `--provider` | `anthropic`, `openai`, `ollama` or `claudecode`. Also written into `config.yaml` so later commands inherit it |
| `--model` | provider-specific model override |
| `--instructions` | standing constraints applied to *every* task — "Use chi, no ORM, table-driven tests" |
| `--template` | start from a built-in plan instead of asking the AI. `cloop templates` lists them |
| `--max-steps` | ceiling on steps for the project; `0` (the default) is unlimited |
| `--max-minutes` | per-task wall-clock budget; a task that overruns is interrupted and marked timed out |
| `--skip-clarify` | skip the interactive question round described below — the flag automation wants |
| `-i` / `--interactive` | the step-by-step setup wizard |

The wizard also starts on its own if you run `cloop init` with no goal, no
`--template`, no `--provider` and a terminal attached — so a bare `cloop init`
in a script is not the same thing as one in a shell. `--template` is the flag
that changes what happens next: a templated project starts with its tasks
already in the plan, so `cloop run` executes them directly instead of calling
the provider to decompose anything.

---

## What `.cloop/` now holds

```
.cloop/
  state.db        the canonical store — goal, plan, tasks, steps, costs, events
  config.yaml     provider, model, API keys, and everything else you can set
```

**`state.db` is SQLite, and it is the only source of truth.** `state.db-wal` and
`state.db-shm` appear beside it as soon as anything writes; they are WAL
sidecars, they belong to the database, and they must never be copied or moved on
their own.

`state.json` is **legacy**, which makes the `State:` line printed above
misleading — no such file is created. The name survives only so that a project
made by an older cloop is detected and migrated into `state.db` on first load,
and `cloop doctor` warns that it was not found for the same reason. Trust `ls`,
not the banner.

`init` also appends `.cloop/env.yaml` to your `.gitignore`, because that file is
where per-project environment secrets land. `config.yaml` is safe to commit only
if you have kept API keys out of it — see
[Configuration](../reference/configuration.md) for the full key list and
[Secrets](../guides/secrets.md) for the credential model proper.

More appears as you use it: `plan-history/` (a snapshot per plan mutation),
`tasks/<id>-<slug>.md` (one artifact per completed task), `clarification.json`,
`checkpoints/`.

---

## The first run

```bash
cloop run
```

Three things happen, in order.

**A round of questions**, if stdin is a terminal and you did not pass
`--skip-clarify`. cloop asks the provider to generate clarifying questions about
your goal and puts them to you before spending anything on a plan, under a
`Goal clarification` heading and a `Q1:` prompt per question. Enter skips one.
Answers are saved to `.cloop/clarification.json` and reused: the next run prints
`(Using goal clarification from previous session)` instead of asking again.

**Decomposition.** The provider turns the goal, your standing instructions and
those answers into a prioritised plan, which is saved before any of it is
executed:

```
🧠 cloop PM — AI Product Manager Mode
   Provider: claudecode
   Goal: Add a health check endpoint to the HTTP server

Decomposing goal into tasks...

Task Plan (3 tasks):
  1. [P1] Add a /healthz handler returning 200 and a JSON body
       …
```

**Execution.** Tasks are taken in priority order, skipping any whose
dependencies are not yet satisfied, and each one is a separate provider call
whose result is written back to the plan:

```
━━━ Task 1/3: Add a /healthz handler returning 200 and a JSON body ━━━

✓ Task 1 complete: Add a /healthz handler returning 200 and a JSON body
```

A task that reports failure is retried with a mutated prompt (`--no-heal` turns
that off), and three consecutive failures stop the run — `--max-failures`
changes the number. When the queue drains:

```
🎉 All tasks complete! Goal achieved.
```

Two flags are worth using on a first run: `--plan-only` stops after
decomposition so you can read the plan before anything touches your files, and
`--dry-run` prints the prompts cloop *would* send without calling the provider
at all. The long tail — parallelism, verification passes, budgets, git
integration — is in `cloop run --help` and the
[command reference](../reference/commands.md#cloop-run).

---

## Watching it

`cloop status` is the one-screen answer. Here it is on a project whose plan
exists but has not been executed yet:

```console
$ cloop status
Goal:     Add a health check endpoint to the HTTP server
Status:   initialized
Provider: claudecode (default)
Mode:     product manager
Tasks:    0/3 tasks complete
          [ ] Task 1: Add a /healthz handler returning 200 and a JSON body
          [ ] Task 2: Write a table-driven test for the /healthz handler
          [ ] Task 3: Document the endpoint in the README
Created:  2026-09-08 23:47
Updated:  2026-09-08 23:47
```

`cloop log` is the history — every step, with the provider's output. It is
verbose by default, so the flags matter: `--last 5` for the tail, `--lines 20`
to cap each step's output, `--step 3` for one in full, `--grep <text>` to find
the step that mentions something, and `--json` for a machine.

For anything longer than a few tasks, run the dashboard in a second terminal:

```console
$ cloop ui
cloop dashboard running at http://localhost:8080
```

`--port` moves it, `--no-browser` stops it opening a tab. It streams progress
live and can start and stop runs. It is **unauthenticated on loopback by
default**, which is correct for your own machine and wrong for anything else; if
it needs to be reachable, mint a scoped token with `cloop hub token create`
rather than using the deprecated static `--token`, and terminate TLS
(`--tls-cert`/`--tls-key`, or `ui.tls` in the config). The
[dashboard guide](web-ui.md) covers it properly, and the
[security model](../security/model.md) explains what the boundary is worth.

---

## Steering the plan

The plan is data. You are meant to edit it.

```console
$ cloop task list
Tasks: 0/3 tasks complete

  [ ] #1 [P1] Add a /healthz handler returning 200 and a JSON body
  [ ] #2 [P2] Write a table-driven test for the /healthz handler
  [ ] #3 [P3] Document the endpoint in the README
```

`cloop task next` shows what the scheduler will pick up next; `cloop task show
<id>` prints one task in full, including its result and the artifact written for
it. Adding work is a sentence, which the provider structures into a title,
description, priority, role and suggested dependencies and shows you before it
is appended:

```bash
cloop task add "the healthz handler should report the database connection state"
```

`--auto` skips the confirmation, `--no-ai` takes your text as the title
verbatim, and `--priority`, `--role`, `--deadline`, `--max-minutes` and
`--depends-on '1,2'` set fields directly. The rest of the vocabulary is
`cloop task edit`, `move`, `remove`, `skip`, `done`, `fail`, `reset`, `tag` and
`annotate` — plus a large set of AI-assisted operations (`split`, `merge`,
`decompose`, `reorder`) documented under
[`cloop task`](../reference/commands.md#cloop-task).

New tasks join the same queue the run is working through, so you can add one
while a run is in progress and it will be picked up in priority order.

---

## Stopping and resuming

Ctrl+C is a pause, not a kill: cloop prints
`⏸ Pausing after current step...` and lets the step finish so its result is
saved. Because the plan lives in `state.db` rather than in the process, resuming
is just running the same command again — the next `cloop run` opens with
`Resuming plan: 1/3 tasks complete`.

Other ways to stop deliberately: `--steps N` runs at most N steps this session,
`--timeout 30m` bounds the whole session, and `--token-budget` or `--cost-limit`
stop on spend. The step and token ceilings say so on the way out —
`⏸ Reached --steps limit (5). Run 'cloop run' to continue.` — and all of them
leave the plan exactly as resumable as Ctrl+C does.

For recovering rather than pausing:

| Command | Does |
| --- | --- |
| `cloop run --retry-failed` | reset failed tasks to pending and try them again |
| `cloop run --replan` | discard the plan and decompose the goal from scratch |
| `cloop goal "<new goal>"` | change the goal without reinitialising |
| `cloop reset` | clear progress, keep the goal |
| `cloop clean` | remove `.cloop/` entirely |

---

**Next:** [Concepts](concepts.md) — goals, plans, tasks, steps and providers,
and how they fit together.
