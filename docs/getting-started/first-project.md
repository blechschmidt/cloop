# Your first project

This page takes you through a first project from start to finish. You set a
goal, look at the plan cloop makes from it, run the plan, and then watch,
change and stop the run.

cloop doesn't work on your goal directly. It first splits the goal into a
numbered list of tasks, saves the list, and then works through it one task at a
time. You can read and change the list at any point, including while a run is
going.

- [Setting a goal](#setting-a-goal)
- [What `.cloop/` now holds](#what-cloop-now-holds)
- [The first run](#the-first-run)
- [Watching it](#watching-it)
- [Steering the plan](#steering-the-plan)
- [Stopping and resuming](#stopping-and-resuming)

---

## Setting a goal

Run cloop inside the repository you want to change. cloop edits the files in
the directory you run it from, so a scratch clone is a good place for a first
try.

```console
$ cd ~/src/demo-api
$ cloop init "Add a health check endpoint to the HTTP server"
✓ cloop initialized
  Goal: Add a health check endpoint to the HTTP server
  Max steps: 0
  State: /home/you/src/demo-api/.cloop/state.db
  Config: /home/you/src/demo-api/.cloop/config.yaml
  Provider: claudecode (default)

Run 'cloop run' to decompose your goal into tasks and execute them.
```

The goal is a sentence that describes the result you want. cloop stores it and
builds every task's prompt from it, so a vague goal leads to vague tasks.

These `cloop init` flags are useful for a first project:

| Flag | What it does |
| --- | --- |
| `--provider` | `claudecode` (the default), `copilot`, `anthropic`, `openai` or `ollama`. It is saved in `config.yaml`, so later commands use it too |
| `--model` | use a particular model from that provider |
| `--instructions` | rules for *every* task, such as "Use chi, no ORM, table-driven tests" |
| `--template` | start from a built-in plan instead of having the model write one. `cloop templates` lists them |
| `--max-steps` | the most steps the project may take; `0` (the default) means no limit |
| `--max-minutes` | a time limit per task; a task that takes longer is stopped and marked as timed out |
| `--skip-clarify` | skip the questions described below, which is what you want in a script |
| `-i` / `--interactive` | a step-by-step setup wizard |

If you run `cloop init` in a terminal with no goal, no `--template` and no
`--provider`, the wizard starts by itself. In a script, with no terminal
attached, it doesn't. With `--template`, the project starts with the
template's tasks already in the plan, and `cloop run` starts on them right away
instead of asking the model for a plan.

---

## What `.cloop/` now holds

```
.cloop/
  state.db        the canonical store — goal, plan, tasks, steps, costs, events
  config.yaml     provider, model, API keys, and everything else you can set
```

`state.db` is a SQLite database, and everything cloop knows about the project
is in it. As soon as anything writes to it, two more files appear next to it,
`state.db-wal` and `state.db-shm`. They are part of the database, so never copy
or move them on their own.

Older versions of cloop kept the project in `state.json`. cloop no longer
writes that file. If it finds one, it moves the contents into `state.db` the
first time it opens the project.

`init` also adds `.cloop/env.yaml` to your `.gitignore`, because that is where
per-project environment secrets are stored. You can commit `config.yaml` as long
as you keep API keys out of it. See [Configuration](../reference/configuration.md)
for every key, and [Secrets](../guides/secrets.md) for how cloop handles
credentials.

More files appear as you go: `plan-history/` (a snapshot each time the plan
changes), `tasks/<id>-<slug>.md` (a record of each completed task),
`clarification.json` and `checkpoints/`.

---

## The first run

```bash
cloop run
```

Three things happen.

**cloop asks you a few questions**, if you are in a terminal and didn't pass
`--skip-clarify`. It has the model come up with questions about your goal and
asks them before it spends anything on a plan, under a `Goal clarification`
heading with a `Q1:` prompt for each question. Press Enter to skip a question.
Your answers are saved in `.cloop/clarification.json` and reused, so the next
run prints `(Using goal clarification from previous session)` instead of asking
again.

**The model writes the plan.** From your goal, your standing instructions and
your answers, it produces a list of tasks in priority order. cloop saves the
plan before running any of it:

```
🧠 cloop PM — AI Product Manager Mode
   Provider: claudecode
   Goal: Add a health check endpoint to the HTTP server

Decomposing goal into tasks...

Task Plan (3 tasks):
  1. [P1] Add a /healthz handler returning 200 and a JSON body
       …
```

**cloop works through the tasks** in priority order, skipping any task whose
dependencies aren't finished yet. Each task is a separate call to the provider,
and its result is saved in the plan:

```
━━━ Task 1/3: Add a /healthz handler returning 200 and a JSON body ━━━

✓ Task 1 complete: Add a /healthz handler returning 200 and a JSON body
```

If a task fails, cloop retries it with a modified prompt (`--no-heal` turns
this off). Three failures in a row stop the run, and `--max-failures` changes
that number. When every task is finished you see:

```
🎉 All tasks complete! Goal achieved.
```

Two flags are useful on a first run. `--plan-only` stops once the plan is
written, so you can read it before anything touches your files. `--dry-run`
prints the prompts cloop would send, without calling the provider at all.
Parallel tasks, verification, budgets, git integration and the rest are
described in `cloop run --help` and the
[command reference](../reference/commands.md#cloop-run).

---

## Watching it

`cloop status` gives you an overview on one screen. Here it is for a project
whose plan has been written but not run yet:

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

`cloop log` shows the history: every step, with the provider's output. It
prints a lot by default, so these flags help: `--last 5` for the last five
steps, `--lines 20` to shorten each step's output, `--step 3` for one step in
full, `--grep <text>` to find the steps that mention something, and `--json`
for machine-readable output.

For anything longer than a few tasks, start the dashboard in a second terminal:

```console
$ cloop ui
cloop dashboard running at http://127.0.0.1:8080, listening on 127.0.0.1:8080
```

`--port` changes the port and `--no-browser` stops it from opening a browser
tab. The dashboard shows progress as it happens and can start and stop runs.
**It has no sign-in by default, so it only listens on loopback**, which is fine
on your own machine. If other people need to reach it, set up sign-in first
(OIDC under `ui.oidc`) and TLS (`--tls-cert`/`--tls-key`, or `ui.tls` in the
config). A token from `cloop hub token create` doesn't replace sign-in: it
limits what a script that presents it may do, but it doesn't stop a request
that presents no token at all. The [dashboard guide](web-ui.md) covers this in
detail, and the [security model](../security/model.md) explains what sign-in
protects.

---

## Steering the plan

You can change the plan whenever you like.

```console
$ cloop task list
Tasks: 0/3 tasks complete

  [ ] #1 [P1] Add a /healthz handler returning 200 and a JSON body
  [ ] #2 [P2] Write a table-driven test for the /healthz handler
  [ ] #3 [P3] Document the endpoint in the README
```

`cloop task next` shows which task cloop will pick up next, and
`cloop task show <id>` prints one task in full, including its result and the
record written for it. To add work, describe it in a sentence. The provider
turns it into a title, a description, a priority, a role and suggested
dependencies, and shows you the result before adding it:

```bash
cloop task add "the healthz handler should report the database connection state"
```

`--auto` adds the task without asking, `--no-ai` uses your text as the title
unchanged, and `--priority`, `--role`, `--deadline`, `--max-minutes` and
`--depends-on '1,2'` set fields directly. To change tasks there are
`cloop task edit`, `move`, `remove`, `skip`, `done`, `fail`, `reset`, `tag` and
`annotate`, plus commands that ask the model for help, such as `split`,
`merge`, `decompose` and `reorder`. They are all described under
[`cloop task`](../reference/commands.md#cloop-task).

New tasks join the queue the run is working through, so you can add a task
while a run is going and it will be picked up in priority order.

---

## Stopping and resuming

Ctrl+C pauses the run. cloop prints
`⏸ Stopping — the task in progress goes back to pending and the next run picks it up...`,
interrupts the task it was working on, and sets that task back to `pending`
with a note saying why. A stopped task doesn't count as failed, so nothing that
depends on it is skipped, and tasks that had already finished keep their
results. The Stop button in the dashboard does the same, wherever the run is
executing. Because the plan is stored in `state.db`, you resume by running the
same command again: the next `cloop run` starts with
`Resuming plan: 1/3 tasks complete` and begins the interrupted task again.

You can also set limits in advance. `--steps N` runs at most N steps in this
session, `--timeout 30m` limits the length of the whole session, and
`--token-budget` or `--cost-limit` stop the run once it has spent that much.
The step and token limits tell you when they stop a run
(`⏸ Reached --steps limit (5). Run 'cloop run' to continue.`), and all of them
leave the plan ready to resume, just as Ctrl+C does.

To recover from a problem rather than pause:

| Command | What it does |
| --- | --- |
| `cloop run --retry-failed` | set failed tasks back to pending and try them again |
| `cloop run --replan` | throw the plan away and make a new one from the goal |
| `cloop goal "<new goal>"` | change the goal without starting over |
| `cloop reset` | clear the progress but keep the goal |
| `cloop clean` | delete `.cloop/` completely |

---

**Next:** [How cloop works](concepts.md): goals, plans, tasks, steps and
providers, and how they fit together.
