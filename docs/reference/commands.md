# Command reference

Every `cloop` command and its flags. For concepts, see the
[documentation index](../README.md). For the executor and security
configuration keys, see [Configuration](configuration.md).

## Finding a command

`cloop --help` lists the commands in nine groups:

| Group | What is in it |
|-------|---------------|
| **Core workflow** | `init`, `run`, `status`, `log`, `goal`, `queue`, `watch`, `reset`, `clean` |
| **Plan and tasks** | `task`, `plan`, `requirements`, `milestone`, `sprint`, `suggest`, `scope`, and the other commands that shape the plan |
| **Hub, executors and serving** | `ui`, `serve`, `hub`, `executor`, `egress`, `agent`, `daemon`, `workspace`, `session`, and `login`, `remote` and `knowledge` for working with a hub from a terminal |
| **Secrets, access and spend** | `secret`, `env`, `config`, `budget`, `cost`, `audit`, `audit-log`, `events`, `project` |
| **Insight and reporting** | `report`, `retro`, `standup`, `insights`, `metrics`, `search`, `trace`, and other read-only views |
| **AI assistants** | `ask`, `chat`, `shell`, `do`, `ai-pair`, `kb`, `memory`, `skill`, `recipe`, `flow` |
| **Providers and models** | `providers`, `profile`, `router`, `tune`, `bench`, `compare`, `cache` |
| **Integrations and delivery** | `github`, `sync`, `ci`, `release`, `pr`, `review`, `notify`, `plugin` |
| **Maintenance and diagnostics** | `doctor`, `db`, `migrate`, `compact`, `snapshot`, `upgrade`, `version` |

`cloop task` and `cloop plan` group their subcommands the same way. Run
`cloop task --help` to see them.

There are three health checks:

```bash
cloop doctor            # environment, configuration, and provider reachability
cloop config validate   # validate .cloop/config.yaml and the project state
cloop hub doctor        # control-plane readiness for a hosted hub
```

### Hidden AI advisories

The `ai-*` commands under `cloop task` and `cloop plan` each make one provider
call and print a report. The ones that can change the plan only do so with
`--apply`. Four have no `--apply` at all and only give advice: `task ai-coach`,
`task ai-standup`, `plan ai-brief` and `plan ai-roadmap`. `plan ai-roadmap`
writes to `.cloop/roadmaps/` unless you pass `--no-save`. They are hidden from
the help listing to keep it short, but you can still run and script them at the
same paths:

```bash
cloop task ai-acceptance-criteria   cloop task ai-blocker      cloop task ai-coach
cloop task ai-complexity            cloop task ai-impact       cloop task ai-naming
cloop task ai-risk-matrix           cloop task ai-standup      cloop task ai-what-if
cloop plan ai-brief                 cloop plan ai-epic         cloop plan ai-roadmap
```

### Model calls the dashboard dispatches

The dashboard doesn't call a project's model itself. Its Split preview,
dictation's Revise, the blocker analysis and the plan assistant run these
commands on the project's executor, with the caller's Claude account, and read
the result from a framed JSON payload (`pkg/clijson`). `cloop task revise` and
`cloop plan chat` are hidden, because only the hub builds their arguments. With
`--json`, `cloop task ai-blocker <id>` frames its report too:

```bash
cloop task decompose <id> --dry-run --json
cloop task revise <id> --instruction=… --description=… [--title=…] --json
cloop task ai-blocker <id> --json
cloop plan chat --message=… [--history='[{"role":"user","content":"…"}]'] --json
```

---

## Commands Reference

### `cloop init [goal]`

Initialize a new project with a goal.

```bash
cloop init "Build a CLI tool that converts CSV to JSON"
cloop init --max-steps 20 "Refactor to clean architecture"
cloop init --model claude-opus-4-6 --instructions "Use Go, no external deps" "Build a web scraper"
cloop init "Build a full REST API"
```

> Every project runs in Product Manager mode: cloop splits the goal into a task
> plan you can see, and works through it. The old free-form feedback loop
> (`--pm`/non-PM) has been removed, so all changes go through the task pipeline
> and can be audited in the UI.

| Flag | Default | Description |
|------|---------|-------------|
| `--max-steps` | `0` (unlimited) | Maximum number of autonomous steps |
| `--instructions` | | Additional constraints for the AI |
| `--model` | | Model override |
| `--effort` | | Model reasoning-effort level: `low`, `medium`, `high`, `xhigh`, `max` (claudecode and copilot) |
| `--provider` | | Provider override |

### `cloop run`

Start or continue the autonomous task pipeline.

```bash
cloop run
cloop run --provider anthropic
cloop run --auto-evolve
cloop run --model claude-opus-4-6 --step-timeout 15m
cloop run --add-steps 10      # extend max if paused at limit
cloop run --dry-run           # show prompts without executing
cloop run --plan-only         # decompose goal into tasks, then stop
cloop run --retry-failed      # retry previously failed tasks
cloop run --replan            # discard plan and re-decompose
cloop run --require-committed=pushed   # done means committed and pushed (stored with the project)
cloop run --follow-builds     # adopt newly deployed builds at task boundaries (stored with the project)
```

| Flag | Default | Description |
|------|---------|-------------|
| `--provider` | from config | AI provider to use |
| `--model` | from config | Model override |
| `--effort` | from state/config | Model reasoning-effort level: `low`, `medium`, `high`, `xhigh`, `max` (claudecode and copilot) |
| `--auto-evolve` | `false` | After goal completion, keep discovering new tasks |
| `--innovate` | `false` | Innovation mode: push evolve toward novel capabilities |
| `--step-timeout` | `0` (disabled) | Timeout per step (e.g. `10m`). When unset, `step_timeout` from the config applies |
| `--max-tokens` | `0` | Max output tokens per step |
| `--add-steps` | `0` | Add more steps to max before running |
| `--steps` | `0` | Run at most N steps this session (not persisted) |
| `--dry-run` | `false` | Show prompts without running |
| `--plan-only` | `false` | Decompose tasks but don't execute |
| `--retry-failed` | `false` | Retry failed tasks |
| `--replan` | `false` | Discard existing plan and re-decompose |
| `--max-failures` | `3` | Consecutive task failures before the run stops |
| `--context-steps` | `3` | Recent steps to include in prompts (0 = none) |
| `--step-delay` | | Delay between steps (e.g. `5s`, `1m`) |
| `--on-complete` | | Shell command to run on goal completion (e.g. `notify-send done`) |
| `--token-budget` | `0` | Stop when cumulative tokens reach this limit (0 = unlimited) |
| `--notify` | `false` | Send OS desktop notifications on task done, task failed, and session complete |
| `--require-committed[=VALUE]` | | Set [done means committed](../guides/done-means-committed.md) for the project, then run: `committed` (the bare flag), `pushed`, or `off`. Stored with the project, like `cloop require-committed` |
| `--requirements-gate=MODE` | | Set the [requirements gate](../guides/requirements.md#requirement-gated-completion) for the project, then run: `linked`, `linked+must` or `off`. Stored with the project, like `cloop requirements gate`; a `requirements.gate` declared in `config.yaml` is applied first |
| `--follow-builds[=false]` | off | When a newer cloop build is deployed at the path this run was started from, adopt it at the next task boundary, in the same process and with the same live log, instead of running the old build until the run ends. Host-process runs on Linux only. Stored with the project, like the Overview's *Follow New Builds* badge; see [Following new builds](configuration.md#following-new-builds) |
| `-v, --verbose` | `false` | Show full step output (no truncation) |

**Stopping:** Press `Ctrl+C` to pause gracefully. Run `cloop run` again to resume.

**A new build while it runs:** a run keeps the build it started with until it
ends. With `--follow-builds`, or after *Adopt at next task boundary* on the
Overview, it adopts the new build at its next task boundary instead. It first
checks the deployed binary (`version --json` must report a strictly higher
`sequence` and a `schema` at least as new as the database's), then re-executes
itself with it. If the check fails, the refusal is written to the journal
(`run_adoption`) and the run carries on. See *Long-lived runs after an upgrade*
in the runbook.

### `cloop require-committed`

Show or set **done means committed**: when an agent says a task is done, cloop
accepts it only once the agent's changes are committed (with `pushed`, also
pushed to the upstream of their branch). If the attempt left paths uncommitted,
or commits unpushed, the task goes back to the agent with a list of them, at
most twice. A task that still ends that way goes back to `pending` as an
`uncommitted_work` abort, with its work left in the tree. See
[Done means committed](../guides/done-means-committed.md).

```bash
cloop require-committed              # show the setting
cloop require-committed committed    # on
cloop require-committed pushed       # on, and pushed
cloop require-committed off          # off (remembers "pushed" for next time)
cloop require-committed --json
```

The setting is stored in the project's state, goes with it to isolating
executors, and takes effect in a running `cloop run` at its next task. In the
dashboard, use the *Done = Committed* and *…and Pushed* badges on a project's
Overview.

### `cloop status`

Show the project's status: provider, progress and token usage, and, once it has
been set, what "done" requires (`Done:     only once committed
and pushed`; see `cloop require-committed`). While a run is executing, it also
shows which build that run is on, compared with the build of the `cloop` you ran
(`Build:    running dev+g4e35bf6 (sequence 831 on main) (pid 4242), 132 builds
behind this cloop`), whether the project follows new builds (`Follow:`), and a
pending adoption request (`Adopt:`). With `--json`, the same information is in
`run_build`, `run_owner`, `follow_builds` and `adopt_request`.

```
Goal:     Build a REST API with auth
Status:   complete
Provider: anthropic
Progress: 5/10 steps
Tokens:   12450 in / 3820 out
Created:  2026-05-01 14:00
Updated:  2026-05-01 14:15
```

### `cloop version`

Print the build: version, Go toolchain, platform, the executor protocol and,
for a stamped build, the commit and its position on main.

```bash
cloop version
cloop version --json   # {"version","go","os","arch","protocol","min_protocol","commit","sequence","schema"}
```

The device installer, and a run adopting a new build, run `--json` to check a
binary before trusting it, so it has no side effects: it loads no configuration
and opens no database. `schema` is the newest state-database migration the
build contains. A run refuses to adopt a build whose `schema` is older than its
project's database.

### `cloop log`

Show step history.

```bash
cloop log              # all steps (truncated output)
cloop log --step 3     # specific step
cloop log --last 5     # show only the 5 most recent steps
cloop log --lines 0    # full output (no truncation)
cloop log --json       # machine-readable JSON array
cloop log --grep "error"  # filter steps containing "error" (case-insensitive)
```

### `cloop goal`

Show or change the project goal without initializing the project again. Steps, the task plan and settings are kept.

```bash
cloop goal                        # show current goal
cloop goal "New goal text"        # update the goal in-place
```

### `cloop export`

Export the session as a markdown report (goal, steps, task plan).

```bash
cloop export                  # print to stdout
cloop export -o report.md     # write to file
```

### `cloop report`

Generate a progress report with task completion status, timeline, token usage and cost estimates.

```bash
cloop report                         # terminal report
cloop report --format md             # markdown report to stdout
cloop report --format md -o out.md   # save markdown to file
cloop report --show-outputs          # include step/task output excerpts
```

| Flag | Default | Description |
|------|---------|-------------|
| `--format` | `terminal` | Output format: `terminal`, `md`/`markdown`, `html` |
| `--show-outputs` | `false` | Include step/task output excerpts |
| `-o, --output` | | Save report to file instead of stdout |

### `cloop providers [--test]`

List all providers with their configuration status.

```bash
cloop providers         # show all providers + config
cloop providers --test  # also verify connectivity
```

### `cloop config`

Manage project configuration stored in `.cloop/config.yaml`.

```bash
cloop config show                          # show config (keys masked)
cloop config set provider anthropic        # set default provider
cloop config set anthropic.api_key sk-...  # set a value
```

Supported keys: `provider`, `anthropic.api_key`, `anthropic.model`, `anthropic.base_url`, `openai.api_key`, `openai.model`, `openai.base_url`, `ollama.base_url`, `ollama.model`, `claudecode.model`, `copilot.model`, `copilot.effort`, `webhook.url`, `github.token`, `github.repo`

### `cloop task`

Manage the tasks in the plan.

```bash
cloop task list                    # show all tasks with status
cloop task list --json             # output tasks as JSON array (for scripting)
cloop task show <id>               # show full task details (untruncated)
cloop task show <id> --json        # output task as JSON
cloop task next                    # show the next pending task (preview before running)
cloop task add "Title" --desc "Description" --priority 1
cloop task edit <id> --title "New title" --priority 2
cloop task skip <id>               # mark as skipped
cloop task done <id>               # mark as done
cloop task fail <id>               # mark as failed
cloop task reset <id>              # reset to pending
cloop task remove <id>             # remove from plan
cloop task move <id> up            # run a task, or a review gate, one place sooner (or down)
```

#### `cloop task gate`

Human review gates: entries in the task list where a run stops until someone
approves them. See [Stopping a run for review](../guides/human-review-gates.md).

```bash
cloop task gate add                          # at the end of the queue
cloop task gate add --after 4                # right after task 4
cloop task gate add --before 7 --title "Check the schema" --note "Look at the migration"
cloop task gate approve <id>                 # let runs continue past it
cloop task gate reopen <id>                  # make runs stop there again
```

| Flag | Default | Description |
|------|---------|-------------|
| `--after` | | `add`: put the gate right after this task (the head of the queue if that task has already run) |
| `--before` | | `add`: put the gate right before this task, which must still be queued |
| `--title` | `Human review` | `add`: what the gate is for |
| `--note` | | `add`: what the reviewer should look at |
| `--json` | `false` | `add`: print the new gate as JSON |

`cloop task done <id>` on a gate approves it, `cloop task reset <id>` closes it
again and `cloop task skip <id>` bypasses it. `cloop task approve <id>` approves
a gate as well. Approving refuses to run inside a task's run, where the agent's
environment names the task.

#### `cloop task attachments`

The files attached to a task: what its runs left in their outbox
(`.cloop/attachments/outbox/<task-id>/`, which the agent finds in
`$CLOOP_TASK_ATTACHMENTS`) and files attached by hand. See
[Task attachments](../guides/attachments.md).

```bash
cloop task attachments <id>                      # list (alias: list, ls)
cloop task attachments add <id> <file>...        # attach by hand
cloop task attachments get <id> <attachment>     # save under its own name
cloop task attachments remove <id> <attachment>  # delete (audited)
```

| Flag | Default | Description |
|------|---------|-------------|
| `--json` | `false` | Print machine-readable JSON (every subcommand) |
| `--name` | | `add`: attach the file under this name (one file only) |
| `--note` | | `add`: a note shown with the attachment |
| `-o, --output` | the attachment's name | `get`: where to save it; `-` prints it to stdout |
| `--force` | `false` | `get`: overwrite an existing file |

`<attachment>` is an attachment's id, an id prefix of at least six characters,
or its name. Limits: 32 MiB per file, 100 files and 128 MiB per task, 1 GiB per
project.

### `cloop requirements`

What the project must keep doing, and whether it still does. See the
[Requirements guide](../guides/requirements.md). Aliases: `requirement`, `req`,
`reqs`.

```bash
cloop requirements add "<title>" [-d <details>] [--test <command>]... [--priority must|should|could] [--status draft|approved|deprecated] [--tag <tag>]...
cloop requirements list [--json]
cloop requirements show <id> [--json]
cloop requirements edit <id> [--title …] [-d …] [--test …]... [--clear-tests] [--priority …] [--status …] [--tag …]
cloop requirements remove <id>
cloop requirements check [id...] [--ai] [--status <s>,…|--all] [--file <spec>] [--timeout <d>]
cloop requirements prove <id>... [--base <commit>] [--timeout <d>]
cloop requirements verdict <id> fulfilled|unfulfilled [--note <text>]
cloop requirements history <id> [--limit N] [--json]
cloop requirements export [--file <path>|-] [--force]
cloop requirements import [--file <path>] [--dry-run] [--resolve R-<n>=file|hub]... [--prefer file|hub] [--json]
cloop requirements validate [--file <path>] [--json]
cloop requirements gate [off|linked|linked+must] [--assess|--no-assess] [--json]
cloop requirements draft [--from-goal|--from-file <path>|-] [--max N] [--dry-run] [--json]
cloop requirements lint [id...] [--ai] [--strict] [--all] [--file <spec>] [--json]
cloop requirements approve <id>...|--all-drafts [--json]
cloop requirements plan [--count N] [--dry-run|--yes] [--json]
cloop requirements trace [--json|--markdown|--csv] [--priority must|should|could|none] [--tag <tag>] [--gap <gap>|none] [--limit N] [--after <id>]
```

| Flag (`check`) | Default | Description |
|------|---------|-------------|
| `--ai` | off | Ask the model about the requirements that have no tests; without it they are skipped |
| `--status`, `--all` | `approved` | With no ids, the statuses to check. `--all` checks approved and deprecated requirements. Named requirements are checked whatever their status, except that a draft is never checked until it is approved |
| `--file` | none | Check the requirements in this spec file; needs no hub and no project database, and records nothing |
| `--provider`, `--model` | the project's | The model `--ai` asks |
| `--ai-timeout` | `5m` | How long the model may take over one requirement |
| `--timeout` | none | Stop the whole check after this long |
| `--json`, `--no-record`, `--spec` | off | How the hub runs it on a project's executor: a framed report, nothing recorded, the requirements it sends |

`prove` runs each named requirement's tests at the commit before their
implementation (or at `--base`) and on the project's tree, and reports whether
they fail without the change and pass with it: proven, vacuous, broken or
inconclusive. It never touches the project's checkout. It exits 1 when a proof
is vacuous, broken or could not run. See
[Red-green proofs](../guides/requirements.md#red-green-proofs).

`plan` has the model plan tasks that close the open gaps of the approved
requirements, must requirements first, each linked to the requirements it
closes, and offers them for review. `--yes` adds them all, `--dry-run` adds
none. See
[Planning from the requirements](../guides/requirements.md#planning-from-the-requirements).

`trace` prints the traceability matrix and the spec coverage of the must
requirements (tested, proven, passing and linked). For each approved
requirement, the matrix shows the tasks that implement it and their states, the
commits those tasks produced, its latest verdict with its age and staleness,
its latest proof, and whether it is tested, assessed by the model or a person,
or unverified. Without `--limit` it prints every row. `--after` continues from
the cursor a page printed. See
[Traceability and spec coverage](../guides/requirements.md#traceability-and-spec-coverage).

`gate` shows or sets [requirement-gated completion](../guides/requirements.md#requirement-gated-completion).
With it on, when an agent reports a task done, cloop accepts it only once the
task's linked requirements pass their tests on the project's executor (with
`linked+must`, also every approved must requirement that has tests).
`--assess` asks the model about linked requirements without tests. When
`config.yaml` declares `requirements.gate`, `gate` rewrites the declaration
too.

`check` exits 1 when a requirement is unfulfilled or its check did not work
(or, with `--file`, when the spec file does not validate), so a CI job can use
it as a gate. `--test-timeout` on `add` and `edit` sets how long each test may
run (10 minutes by default).

`draft` has the model draft requirements from the project's goal
(`--from-goal`), a file (`--from-file`, `-` for stdin) or text piped to it. It
writes atomic, testable statements in EARS form, each with acceptance criteria,
a priority, tags and, where the repository makes one obvious, a test, and
stores them as drafts. `--dry-run` shows them without storing any, and `--max`
limits how many (12 by default, 30 at most). The model's answer is parsed
strictly and every proposal must fit within a requirement's limits. A proposal
that doesn't fit, or asks to be anything but a draft, is refused and named.
`approve` approves drafts (nothing checks a draft until then) and records who
approved them. `lint` reports ambiguous wording, compound, duplicate and
contradictory requirements, and approved must requirements with no test. It
exits 1 on an error (with `--strict`, on a warning too). `--ai` also asks the
model about duplicates worded differently and about contradictions. See
[Drafting requirements with the model](../guides/requirements.md#drafting-requirements-with-the-model).
The hub runs these commands on a project's executor with `--json` (and with
`draft`'s hidden `--text`, `--goal` and `--existing`, and `lint`'s `--spec`).

`export`, `import` and `validate` keep the requirements as code, in
`.cloop/requirements.yaml` (`--file` for another path). See
[Requirements as code](../guides/requirements.md#requirements-as-code). `export`
refuses to overwrite a file that has changes the hub doesn't have (`--force`
discards them; `--file -` prints the file). `import` does a three-way merge
and imports nothing while a conflict is unresolved: `--resolve R-<n>=file`
takes the file's version, `=hub` keeps the hub's, and `--prefer` resolves every
conflict not named. `--dry-run` only lists the changes. `validate` reports
every problem with its line number and exits 1 when the file is missing or
invalid. With `--json` it prints the file framed, which is how the hub reads it
on a project's executor.

### `cloop diff`

Show git changes in the current project.

```bash
cloop diff              # all uncommitted changes vs HEAD
cloop diff --stat       # summary (files changed, insertions, deletions)
cloop diff --name-only  # just the list of changed files
cloop diff --session    # diff from when the cloop session was initialized
```

Use `--session` to review everything the AI changed during this session. It
finds the last git commit that existed before `cloop init` was run, and diffs
from there.

### `cloop watch`

Live-refresh the project status while `cloop run` runs in another terminal.

```bash
cloop watch              # refresh every 2s (default)
cloop watch --interval 5s
```

It shows the goal, status, provider, step and task progress, token counts and the last step's output, and stops when the session ends.

### `cloop stats`

Show aggregated session statistics.

```bash
cloop stats
```

Includes step timing (total, average, minimum, maximum), token usage, a cost estimate for known models, and a breakdown of tasks.

### `cloop reset`

Reset progress but keep the goal and configuration.

### `cloop clean`

Remove `.cloop/` directory entirely.

A project with [features](../guides/features.md) keeps their worktrees under
`.cloop/features/`, and each can hold uncommitted work. `clean` refuses to run
while any exist. `cloop clean --force` removes them through git first (their
branches are kept), then the rest of `.cloop/`.

---

## Parallel features

Features let you work on several things in one repository at once. Each
feature is a git worktree on its own branch, with its own task list and run
settings. The [features guide](../guides/features.md) explains how they work;
this section lists the commands.

### `cloop feature new <name>`

Create a feature: a worktree at `.cloop/features/<slug>` on a new branch
`cloop/feature/<slug>`, created from the base branch, with its own `.cloop/`
that starts with the project's provider, model, effort and instructions.

```bash
cloop feature new "Dark mode" --description "Add a dark theme and a toggle"
cloop feature new login --task "Add a login form" --task "Hash passwords" --auto-pr
cloop feature new "Search" --auto-evolve --innovate --parallel --max-parallel 3
cloop feature new hotfix --base release-2.1
```

| Flag | Meaning |
|------|---------|
| `--description` | The feature's goal (default: the name). Its first run plans tasks from it unless `--task` gave some. |
| `--task` | An initial task. Repeat the flag for more; they keep their order. |
| `--base` | Branch to start from and to open the pull request against (default: the remote's default branch, else `main`/`master`). |
| `--auto-evolve`, `--innovate` | The feature's own evolve settings, independent of the project's. |
| `--parallel`, `--max-parallel` | Run the feature's independent tasks concurrently. |
| `--auto-pr` | Have the dashboard open the pull request when the plan completes. |
| `--json` | Machine-readable result (used by the dashboard). |

The project directory must be the top of its git repository. A feature cannot
have features.

### `cloop feature list`

Lists the project's features with their status, task progress, commits ahead of
and behind the base (`+3 -1`, with `*N` for uncommitted changes) and pull
request. `--no-git` skips the git status. Run inside a feature, it lists the
other features of the same project.

### `cloop feature remove <name>`

Remove the feature's worktree, along with its task list and history. This is
refused while a run is in progress or while the worktree has uncommitted
changes.

```bash
cloop feature remove dark-mode                  # branch kept
cloop feature remove dark-mode --delete-branch  # deleted only if merged
cloop feature remove dark-mode --force --delete-branch  # discard and delete regardless
```

### `cloop feature pr [name]`

Push the feature's branch and open a GitHub pull request against its base. If
you run it again while the pull request is open, it pushes new commits and
reports the existing pull request. After a merge with nothing new committed, it
reports the merge.

```bash
cloop feature pr dark-mode
cloop feature pr dark-mode --draft --title "Dark mode (WIP)"
cd .cloop/features/dark-mode && cloop feature pr   # the feature you are in
```

The API token comes from the first of these that has one: `--token`,
`GITHUB_TOKEN`, `GH_TOKEN`, `github.token` in the feature's config, git's
credential helpers for the repository, `gh auth token`, then
`CLOOP_GITHUB_TOKEN`. The hub passes its own token in `CLOOP_GITHUB_TOKEN`, so
it never takes the place of a project's token. `--api-url` (or
`CLOOP_GITHUB_API_URL`) points the command at GitHub Enterprise. A token from
the environment or a config file is only sent to github.com or that host.

### `cloop feature pr-status [name]`

Re-read the pull request from GitHub and record whether it is open, closed or
merged.

---

## Product Manager Mode

cloop splits the goal into a structured task plan, then works on the tasks one
at a time. This is the only mode, so there is no `--pm` flag to turn it on. The
flag was removed along with the old free-form loop.

```bash
# Initialize
cloop init "Build a monitoring dashboard in Go"

# Decompose into tasks first (review before running)
cloop run --plan-only

# Execute the plan
cloop run

# Resume after interruption
cloop run

# Retry any failed tasks
cloop run --retry-failed

# Discard the existing plan and re-decompose
cloop run --replan
```

The agent reports how a task ended with one of these keywords:
- `TASK_DONE`: the task was completed
- `TASK_SKIPPED`: the task doesn't apply or was already done
- `TASK_FAILED`: the task could not be completed

A task can depend on other tasks through `depends_on` in the JSON plan. It
doesn't start until all its dependencies are `done` or `skipped`. If a
dependency fails, every task that depends on it is skipped.

---

## Analysis & Forecasting

### `cloop scope [goal]`

Have the AI assess the project's scope before you start. It estimates the number of tasks, complexity, risks and prerequisites, and recommends an execution mode.

```bash
cloop scope "Build a REST API with auth"
cloop scope                           # analyze current project goal
cloop scope --provider anthropic "Add OAuth support"
```

Output: estimated task count, complexity (low/medium/high/very_high), estimated number of AI calls, risks, prerequisites, assumptions and the recommended execution mode.

### `cloop forecast`

Forecast when the project will be finished, with optimistic, expected and pessimistic scenarios. It draws an ASCII burn-down chart and streams the AI's commentary on the outlook and on ways to finish sooner.

```bash
cloop forecast                       # full forecast (chart + AI narrative)
cloop forecast --quick               # metrics and chart only, no AI
cloop forecast --no-chart            # AI narrative without the chart
cloop forecast --provider anthropic  # use a specific provider
```

| Flag | Default | Description |
|------|---------|-------------|
| `--quick` | `false` | Show metrics and chart only (no AI) |
| `--no-chart` | `false` | Skip the burn-down chart |
| `--provider` | from config | AI provider |
| `--model` | from config | Model override |

### `cloop insights`

Report on the project's health: task velocity, risk score, bottlenecks, a breakdown by role, and the AI's recommendations.

```bash
cloop insights                       # full AI analysis
cloop insights --quick               # metrics panel only, no AI call
cloop insights --provider anthropic
```

| Flag | Default | Description |
|------|---------|-------------|
| `--quick` | `false` | Show metrics only, skip AI analysis |
| `--provider` | from config | AI provider for analysis |
| `--model` | from config | Model override |

### `cloop retro`

Write a sprint retrospective with the AI: what went well, what went wrong, bottlenecks, notes on velocity, key insights and recommended next steps.

```bash
cloop retro                          # terminal retrospective
cloop retro --format md              # markdown output
cloop retro --format md -o retro.md  # save markdown to file
cloop retro --save-memory            # persist insights to project memory
cloop retro --provider anthropic
```

| Flag | Default | Description |
|------|---------|-------------|
| `--format` | `terminal` | Output format: `terminal` or `md` |
| `-o, --output` | | Write output to file (for `--format md`) |
| `--save-memory` | `false` | Save insights to project memory |
| `--timeout` | `120s` | Analysis timeout |
| `--provider` | from config | Provider to use |
| `--model` | from config | Model override |

### `cloop standup`

Write a daily standup report with the AI: what was done, what's next, blockers and a delivery forecast. It can post the report to Slack through a webhook.

```bash
cloop standup                          # AI standup (last 24h)
cloop standup --hours 48               # look back 48 hours
cloop standup --quick                  # metrics only, no AI
cloop standup --post                   # post to Slack webhook
cloop standup --save                   # save to .cloop/standup-DATE.md
cloop standup --format slack           # Slack-formatted output
cloop standup --provider anthropic
```

| Flag | Default | Description |
|------|---------|-------------|
| `--hours` | `24` | Reporting window in hours |
| `--quick` | `false` | Show activity summary only, skip AI |
| `--post` | `false` | Post to configured webhook/Slack |
| `--save` | `false` | Save to `.cloop/standup-YYYYMMDD.md` |
| `--format` | `plain` | Output format: `plain`, `markdown`, `slack` |
| `--provider` | from config | AI provider |
| `--model` | from config | Model override |

To enable Slack posting:
```bash
cloop config set webhook.url https://hooks.slack.com/services/...
```

---

## Planning & Prioritization

### `cloop backlog`

Have the AI build a prioritized product backlog from your codebase. It lists the most valuable improvements, ranked by impact relative to effort.

```bash
cloop backlog                          # analyze current project
cloop backlog --format md              # markdown output
cloop backlog --format md -o backlog.md
cloop backlog --as-tasks               # add top items to PM plan
cloop backlog --max-items 10           # limit to top 10 items
cloop backlog --provider anthropic
```

Each item includes:
- **Type**: `feature`, `bug`, `tech_debt`, `performance`, `security`, `docs`
- **Impact**: `high`, `medium`, `low`
- **Effort**: `xs` (<1h), `s` (1-4h), `m` (4-16h), `l` (1-5d), `xl` (>1wk)

| Flag | Default | Description |
|------|---------|-------------|
| `--format` | `terminal` | Output format: `terminal` or `md` |
| `-o, --output` | | Write output to file |
| `--as-tasks` | `false` | Add backlog items to the task plan |
| `--max-items` | `0` (all) | Maximum number of items to show/add |
| `--provider` | from config | Provider to use |
| `--model` | from config | Model override |

### `cloop prioritize`

Have the AI reorder the tasks. It reviews the current plan and suggests an execution order based on the critical path, dependencies, risks and the value each task delivers.

```bash
cloop prioritize                       # show AI priority suggestions
cloop prioritize --apply               # apply suggestions immediately
cloop prioritize --provider anthropic
```

| Flag | Default | Description |
|------|---------|-------------|
| `--apply` | `false` | Apply suggested priority changes |
| `--dry-run` | `false` | Show suggestions without applying (default) |
| `--provider` | from config | AI provider |
| `--model` | from config | Model override |

### `cloop suggest`

Brainstorm feature ideas for the project, or break a request of your own into a plan of tasks. You review each proposal interactively, and the ones you accept become tasks. The dashboard's **AI Feature Suggestions** panel on the Tasks tab runs the same command. So does **Decompose** next to Add Task: it plans the task typed there and gives every task in the plan the priority and dependencies entered with it.

```bash
cloop suggest                                      # brainstorm 5 ideas
cloop suggest --count 10                           # brainstorm 10 ideas
cloop suggest --input "add OAuth login"            # plan it in as many tasks as it needs
cloop suggest --input "add OAuth login" --count 4  # plan it in exactly 4 tasks
cloop suggest --yes                                # accept everything proposed
```

With `--input`, the proposals are the ordered tasks of one plan, each naming the earlier tasks it depends on. `--count` then sets the plan's length, up to 20. Without it, the plan is as long as the request needs, and a small request may be a single task. Accepted tasks are added to the end of the run queue in plan order and keep their dependencies on each other, even through a task you reject: if task 3 needs task 2 and task 2 needs task 1, rejecting task 2 makes task 3 wait for task 1.

| Flag | Default | Description |
|------|---------|-------------|
| `--input` | | A request to break into a plan of tasks, instead of brainstorming ideas |
| `--count` | 5 ideas; a plan sizes itself | Number of ideas, or with `--input` the number of tasks in the plan (at most 20) |
| `--yes` | `false` | Accept every proposal |
| `--dry-run` | `false` | Show the proposals without prompting or adding tasks |
| `--json` | `false` | Print the proposals as JSON, without prompting or changing the plan |
| `--provider` | from config | Provider to use |
| `--model` | from config | Model override |

### `cloop milestone`

Plan sprints and releases. Group tasks into milestones with deadlines, and forecast completion from velocity.

```bash
cloop milestone create "v1.0 Launch" --deadline 2026-06-15 --tasks 1,2,3
cloop milestone list                   # show all milestones with progress
cloop milestone show "v1.0 Launch"     # detailed status
cloop milestone assign "v1.0 Launch" --tasks 4,5
cloop milestone plan                   # AI generates milestone structure
cloop milestone forecast               # velocity-based completion forecast
cloop milestone delete "Foundation"
```

**`milestone create`** flags:
| Flag | Description |
|------|-------------|
| `--deadline` | Target deadline in `YYYY-MM-DD` format |
| `--description` | One-sentence milestone description |
| `--tasks` | Comma-separated task IDs to assign (e.g. `1,2,3`) |

**`milestone plan`** flags:
| Flag | Description |
|------|-------------|
| `--force` | Replace existing milestones with AI-generated plan |
| `--provider` | AI provider to use |
| `--model` | Model override |

### `cloop simulate <scenario>`

Try out what-if scenarios with the AI before you commit to a change. It estimates the effect on the timeline, risk and task priorities.

```bash
cloop simulate "what if we cut the authentication module?"
cloop simulate "what if the deadline moves up by 2 weeks?"
cloop simulate "what if we add a second engineer to the project?"
cloop simulate "what if we defer all testing tasks to phase 2?"
cloop simulate "what if we focus only on the critical path?" --apply
cloop simulate "what if we switch from REST to GraphQL?" --provider anthropic
```

Output: summary, timeline delta, risk before/after, confidence, recommendations, task changes, trade-offs, and warnings.

| Flag | Default | Description |
|------|---------|-------------|
| `--apply` | `false` | Apply recommended task changes to the project |
| `--quick` | `false` | Print project snapshot only, no AI call |
| `--provider` | from config | AI provider |
| `--model` | from config | Model override |

---

## Code Quality

### `cloop review [commit-range]`

Have the AI review git diffs. It returns a quality score, issues by severity, what was done well, and suggestions.

```bash
cloop review                           # review all uncommitted changes
cloop review --staged                  # review only staged changes
cloop review --last                    # review the last commit
cloop review HEAD~3..HEAD              # review a range of commits
cloop review --task 3                  # include PM task context in review
cloop review --format md               # markdown output
cloop review --format md -o review.md  # save markdown to file
cloop review --quick                   # diff stats only, no AI call
cloop review --provider anthropic
```

| Flag | Default | Description |
|------|---------|-------------|
| `--staged` | `false` | Review only staged changes |
| `--last` | `false` | Review the last commit |
| `--commit` | | Review a specific commit (hash) |
| `--task` | `0` | Include this task's context in the review (task ID) |
| `--format` | `terminal` | Output format: `terminal` or `md` |
| `-o, --output` | | Write output to file |
| `--quick` | `false` | Show diff stats only, no AI call |
| `--timeout` | | Review timeout (e.g. `60s`, `2m`) |
| `--provider` | from config | Provider to use |
| `--model` | from config | Model override |

Issues are graded `critical`, `major`, `minor` or `suggestion`.

### `cloop review gate`

Show or configure the project's review gate: a reviewer, with its own provider
and model, that checks each task's changes before they are pushed or merged.
The agent's pushes are held until the reviewer approves them. See
[Reviewing tasks before they are published](../guides/review-gate.md).

```bash
cloop review gate                                    # show the settings
cloop review gate --enable --provider anthropic --model claude-opus-5-5
cloop review gate --mode block --instructions "Reject changes to migrations/."
cloop review gate --disable
```

| Flag | Default | Description |
|------|---------|-------------|
| `--enable` / `--disable` | | Turn the gate on or off (settings are kept) |
| `--provider` | the project's | `claudecode`, `copilot`, `anthropic`, `openai`, `ollama` |
| `--model` | the project's model on its own provider | Reviewer model |
| `--effort` | provider default | Reviewer reasoning effort (`claudecode` and `copilot`) |
| `--mode` | `fix` | `fix` (send back, then block), `block`, `advisory` |
| `--max-fix-rounds` | `0` (= 2) | How often `fix` sends a task back, at most 5 |
| `--instructions` | | Extra review criteria sent with every review |
| `--json` | `false` | Print the settings as JSON |

---

## Collaboration & Automation

### `cloop ask <question>`

Ask the AI about your project's state, tasks, progress or blockers. It sees the goal, the task plan, recent activity and project memory.

```bash
cloop ask "What are the remaining blockers?"
cloop ask "Summarize what has been done so far"
cloop ask "Which tasks failed and why?"
cloop ask "What should I do next?"
cloop ask "How long will the remaining tasks take?"
cloop ask --provider anthropic "Are there any risks in the current plan?"
```

| Flag | Default | Description |
|------|---------|-------------|
| `--recent-steps` | `3` | Number of recent steps to include in context (0 = none) |
| `--provider` | from config | Provider to use |
| `--model` | from config | Model override |

### `cloop chat`

Chat with an AI product manager. Ask questions, get suggestions, or have it update your task plan.

```bash
cloop chat
cloop chat --provider anthropic
cloop chat --save         # auto-save transcript on exit
```

**Slash commands inside chat:**

| Command | Description |
|---------|-------------|
| `/status` | Show current project status |
| `/tasks` | List all tasks |
| `/help` | Show available commands |
| `/clear` | Clear conversation history |
| `/save` | Save conversation transcript |
| `/quit` | Exit the chat (also: `/exit`, Ctrl+D) |

The AI can change the plan for you: mark tasks done, create tasks and add notes to project memory.

| Flag | Default | Description |
|------|---------|-------------|
| `--provider` | from config | AI provider |
| `--model` | from config | Model override |
| `--timeout` | `120s` | Response timeout |
| `--save` | `false` | Auto-save transcript on exit |

### `cloop compare [prompt]`

Send the same prompt to several AI providers at once, and compare response quality, latency, token counts and cost side by side.

```bash
cloop compare "What is the best way to structure a Go project?"
cloop compare --providers anthropic,openai "Explain REST vs GraphQL"
cloop compare --judge "Write a haiku about software"
cloop compare --task 3           # use a PM task's prompt
cloop compare --format md -o results.md "Design a caching strategy"
cloop compare --full "Summarize microservices best practices"
```

| Flag | Default | Description |
|------|---------|-------------|
| `--providers` | all configured | Comma-separated providers to compare |
| `--judge` | `false` | Use an AI judge to score each response (0-10) |
| `--judge-provider` | first successful | Provider to use as judge |
| `--task` | `0` | Use the prompt of task #N |
| `--format` | `table` | Output format: `table` or `md` |
| `-o, --output` | | Save output to file |
| `--timeout` | `120` | Per-provider timeout in seconds |
| `--full` | `false` | Show full responses (not truncated) |

### `cloop github`

Sync tasks with GitHub Issues and pull requests.

```bash
cloop github sync                      # import open issues as tasks
cloop github sync --repo owner/repo    # specify repo
cloop github sync --labels bug,enhancement  # filter by label
cloop github sync --dry-run            # preview without saving
cloop github push                      # create issues for unlinked tasks
cloop github push --dry-run            # preview what would be created
cloop github push --done               # also close issues for done tasks
cloop github prs                       # list open PRs with CI status
cloop github prs --state all           # include closed PRs
cloop github link 3 42                 # link task #3 to issue #42
cloop github unlink 3                  # remove task #3's issue link
cloop github status                    # show sync overview
```

Configure GitHub access:
```bash
cloop config set github.token ghp_...         # personal access token
cloop config set github.repo owner/repo       # default repo
```

If no repository is configured, it is taken from the `origin` git remote. The token can also come from the `GITHUB_TOKEN` environment variable.

### `cloop agent`

Run an agent in the background that works on tasks unattended, at a regular interval.

```bash
# Start the agent
cloop agent start                      # every 5 minutes
cloop agent start --interval 2m        # every 2 minutes
cloop agent start --provider anthropic # use Claude API

# Monitor the agent
cloop agent status                     # is it running? what's it doing?
cloop agent logs                       # full log stream
cloop agent logs --tail 30             # last 30 lines
cloop agent follow                     # tail log in real time

# Stop the agent
cloop agent stop

# Maintenance
cloop agent clear-logs                 # truncate the log file
```

The agent works on one task per interval, records the results and keeps its state in `.cloop/agent-state.json`. Logs go to `.cloop/agent.log`.

---

## Project Memory

### `cloop memory`

Manage the project's memory, stored in `.cloop/memory.json`. Memory entries are lessons learned that are added to the prompts of future sessions.

```bash
cloop memory list                      # list all stored memory entries
cloop memory add "Always use chi router, not net/http"  # add a manual entry
cloop memory delete <id>               # delete a specific entry by ID
cloop memory clear                     # delete all memory entries
```

Memory entries are also created by:
- `cloop retro --save-memory`, which saves the retrospective's insights
- `cloop chat`, where the AI can add notes during the conversation

### `cloop checkpoint`

Save, restore or list named snapshots of the project state, for example before a risky change or an experiment.

```bash
cloop checkpoint save before-deploy    # save a named checkpoint
cloop checkpoint save                  # save with auto-generated timestamp name
cloop checkpoint list                  # list all saved checkpoints
cloop checkpoint restore before-deploy # restore (current state auto-backed up)
cloop checkpoint delete before-deploy  # delete a checkpoint
```

Checkpoints are stored as `.json` files in `.cloop/checkpoints/`. Restoring one backs up the current state first.

---

## MCP Server (Model Context Protocol)

### `cloop mcp`

Run cloop as an MCP server, so that Claude Desktop, Cursor, Zed and any other client that supports the [Model Context Protocol](https://modelcontextprotocol.io/specification) can use it as a set of tools.

The server speaks JSON-RPC 2.0 over newline-delimited stdio. Log output goes to stderr so that it doesn't corrupt the MCP stream.

```bash
cloop mcp                          # use the configured/auto-detected provider
cloop mcp --provider anthropic     # force a specific provider
cloop mcp --provider openai --model gpt-4o
```

#### Available MCP Tools

| Tool | Description |
|------|-------------|
| `get_status` | Return current orchestrator state: goal, status, step counts, provider |
| `get_plan` | Return the full task plan as JSON, with all task details |
| `add_task` | Append a new task to the current plan (title, description, priority) |
| `complete_task` | Mark a task done by ID with an optional result summary |
| `run_task` | Run a one-off AI prompt with the configured provider |

#### Claude Desktop Configuration

Add to `~/.claude/claude_desktop_config.json` (or the equivalent on your OS):

```json
{
  "mcpServers": {
    "cloop": {
      "command": "cloop",
      "args": ["mcp"],
      "cwd": "/path/to/your/project"
    }
  }
}
```

Claude Desktop then offers the cloop tools in every conversation. You can ask Claude to check the plan's status, add tasks, or run one-off prompts through cloop's provider.

#### Cursor Configuration

In `.cursor/mcp.json` at the project root:

```json
{
  "mcpServers": {
    "cloop": {
      "command": "cloop",
      "args": ["mcp"]
    }
  }
}
```

#### Example Session (raw JSON-RPC)

```json
// Client → cloop
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{}}}

// cloop → Client
{"jsonrpc":"2.0","id":1,"result":{"capabilities":{"tools":{}},"protocolVersion":"2024-11-05","serverInfo":{"name":"cloop","version":"1.0.0"}}}

// Client → cloop
{"jsonrpc":"2.0","method":"initialized"}

// Client → cloop
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_plan","arguments":{}}}

// cloop → Client
{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"{ ... plan JSON ... }"}]}}
```

---

## Web Dashboard

### `cloop ui`

Start the web dashboard. It updates live over a WebSocket (`/api/ws`), or over
SSE where a WebSocket can't be established.

Without a token or OIDC configured, nobody has to sign in, so it listens on
`127.0.0.1` only. With either configured, it listens on every interface.
`--listen` sets a different address. On a hub without sign-in, an address
beyond loopback is refused unless `ui.allow_unauthenticated_network` is set.
Read [Web UI](configuration.md#web-ui-cloop-ui) before exposing the dashboard.

```bash
cloop ui                    # start on default port 8080
cloop ui --port 9090        # use a custom port
cloop ui --no-browser       # don't open the browser automatically
cloop ui --listen 0.0.0.0   # every interface — needs sign-in (ui.oidc or CLOOP_UI_TOKEN)
```

The dashboard shows the project goal, status, step history with outputs, the task list, live progress, and controls to start and stop runs.

| Flag | Default | Description |
|------|---------|-------------|
| `--port` | `8080` | Port to listen on |
| `--listen` | `127.0.0.1` without sign-in, every interface with it | Address to listen on, without the port (overrides `ui.listen`) |
| `--no-browser` | `false` | Do not open the browser automatically |
| `--advertise-url` | `http(s)://127.0.0.1:<port>`, or the bound address when `--listen` names one interface | The URL at which the other hubs serving this directory reach this one (also `CLOOP_CLUSTER_ADVERTISE_URL`, or `CLOOP_CLUSTER_ADVERTISE_HOST` to set only the host) |

Several `cloop ui` processes started in one directory serve it together, as
members of one [hub cluster](../architecture/hub-cluster.md) behind a load
balancer:

```bash
cloop ui --port 8080 --no-browser &
cloop ui --port 8081 --no-browser &
cloop hub cluster status     # the members, the leader, and where each is reached
```

`cloop hub cluster status [--json]` reads the database directly, so it works
even while every member is down. It lists members that stopped within the last
day as gone.

## Working with a hub from a terminal

A terminal signs in to a hub with single sign-on, using device authorization,
and then works with the hub's projects as the person who approved the sign-in.
[Working from a terminal](../getting-started/terminal.md) is the walkthrough;
this section is the reference.

### `cloop login <hub-url>`

Signs this terminal in. It prints a code and the hub's approval page. You
approve the code on that page in a browser signed in to the hub (signing in
again at the identity provider first if that sign-in is older than
`ui.oidc.device_approval_max_age_minutes`). The terminal then gets a **CLI
session**: a session of kind `cli` in the hub's store. Its time limits are
never longer than a browser session's, it is re-checked with the identity
provider on the same rule, it is listed and revoked like any session, and
offboarding ends it.

```bash
cloop login https://cloop.example.com
cloop login https://cloop.internal --ca-file /etc/ssl/internal-ca.pem
cloop login https://cloop.example.com --no-browser --hostname build-box-7
```

| Flag | Default | Description |
|------|---------|-------------|
| `--ca-file` | | PEM bundle to trust for the hub's certificate, stored with the session |
| `--no-browser` | `false` | Print the approval link without opening a browser (a browser is only opened on a desktop session) |
| `--default` | `false` | Make this hub the default. The first hub you sign in to is the default anyway |
| `--hostname` | the host name | What the approval page calls this machine |

The terminal generates its session credential before asking for a code, and
sends the hub only its SHA-256. The approval stores the session under that
digest, and the hub's answer to the terminal's poll contains the session's id
and no secret. `cloop login` checks that the id is its own digest and refuses
anything else. If this terminal already had a session for the hub, the hub ends
it when the new one replaces it.

Exits non-zero when the code is denied (`the sign-in was denied`), expires
(`the code expired before it was approved`), or the hub has no single sign-on or
has terminal sign-in turned off (`ui.oidc.device_login: false`).

### `cloop logout [hub-url]`

Ends this terminal's session at the hub, then deletes it from the credential
file. Without a URL it signs out of the default hub.

| Flag | Description |
|------|-------------|
| `--all` | Sign out of every hub this terminal is signed in to. This also works on a credential file other users can read, so that you can revoke credentials that may have been copied. Every other command refuses such a file, including `logout` of a single hub, which would write the other hubs' credentials back into a file that looks private again |
| `--force` | Delete the credentials even if the hub cannot be reached to end the session (which then stays valid there until it expires or is revoked from the dashboard) |

A session the hub has already ended (revoked, expired or idle) is removed
without an error. The credential file is deleted once it holds no hubs.

### `cloop whoami [hub-url]`

Asks the hub about this terminal's session: identity, session kind and host
name, role, hub-wide permissions, and how long the session has left. `--json`
prints the hub's `/api/me` answer with the hub URL and session id added. If the
session has ended, it says so and exits non-zero.

### `cloop remote`

Work with a hub's projects as the signed-in identity. Each subcommand makes the
same API call as the dashboard, so the hub authorises it as it would the
dashboard's button. A `<project>` is a name, an index or a path, as
`cloop remote projects` lists them. An ambiguous name is refused, and the error
lists the matches.

```bash
cloop remote init [--goal <text>] [--executor <id|name>] [--repo owner/name]... [--grant <secret>[,key=value]...]... [--run] [--json]
cloop remote executors [--json]
cloop remote repos list|add|remove <project> ... [--json]
cloop remote grants request|list|withdraw ... [--json]
cloop remote approvals list|approve|deny ... [--json]
cloop remote features start|list|pr <project> ... [--json]
cloop remote projects [--json]
cloop remote tasks <project> [--status pending] [--json]
cloop remote add <project> <title> [--description <text>] [--json]
cloop remote run <project>
cloop remote stop <project>
cloop remote logs <project> [--follow]
```

| Subcommand | Calls | Permission |
|------------|-------|------------|
| `init` | `GET /api/me`, `/api/executors`, `/api/secrets` and `/api/secrets/catalog` for its checks; `POST /api/projects/new` (with the executor and the grants you may make), then the `repos add` calls, `POST /api/grant-requests` for what needs an approver, `GET`/`POST /api/projects/{idx}/harness-credential`, and with `--run` `POST /api/run` | `project.write`; `executor.manage` with `--executor`; each grant's own |
| `executors` | `GET /api/executors`, narrowed to the executors whose access list admits you | `executor.read` |
| `repos list` | `GET /api/projects/{idx}/repositories` | `project.read` |
| `repos add` | `GET /api/projects/{idx}/repositories` and `/repositories/available`, then `POST /api/projects/{idx}/repositories`, or `POST /api/grant-requests` if the grant is refused for lack of `secret.grant` | `secret.grant` on the project, else `secret.request` |
| `repos remove` | `DELETE /api/projects/{idx}/repositories`, or a replacing `POST` when the grant keeps other repositories | `secret.revoke`, `secret.grant` on the project |
| `grants request` | `POST /api/grant-requests` | `secret.request` |
| `grants list` | `GET /api/grant-requests` | `secret.request` |
| `grants withdraw` | `POST /api/grant-requests/{id}/withdraw` | `secret.request`, the requester |
| `approvals list` | `GET /api/approvals` | none: the inbox holds what you may decide, empty for anyone who may decide nothing |
| `approvals approve` | `GET /api/approvals`, then `POST /api/grant-requests/{id}/approve` or `POST /api/tokens/{id}/approve` | `secret.grant` hub-wide and on the request's subject, never the requester; `token.admin` and the token's roles |
| `approvals deny` | `GET /api/approvals`, then `POST /api/grant-requests/{id}/deny` | `secret.grant` hub-wide and on the request's subject, never the requester |
| `features start` | `POST /api/projects/{idx}/features` | `project.write` |
| `features list` | `GET /api/projects/{idx}/features` | `project.read` |
| `features pr` | `POST /api/projects/{idx}/features/{slug}/pr` | `project.write` |
| `projects` | `GET /api/projects?indices=1` | `project.read` |
| `tasks` | `GET /api/tasks` | `project.read` |
| `add` | `POST /api/tasks` | `task.mutate` |
| `run` | `POST /api/run` | `run.start` |
| `stop` | `POST /api/stop` | `run.stop` |
| `logs` | `GET /api/livelog`; with `--follow`, the dashboard's WebSocket `/api/ws` | `project.read` |

**Errors.** When the hub refuses a request, its message and code come first,
then each detail it sent, one per line. For a missing permission, that is the
permission and the scope it was checked at, your role there, and how to get it:
from a maintainer of the project (its Members card) or an administrator (the
role mappings), or, for `secret.grant`, by filing a request. If the refusal was
only because your claims were too old, it tells you to sign in again with
`cloop login`.

`logs --follow` prints the run's output, starting with the backlog the hub
replays on connect, and notes on stderr when the run starts and stops. It runs
until you press `Ctrl-C`, or until the hub closes the stream because the
session ended or access to the project was withdrawn. Then it exits non-zero
with the hub's reason.

Persistent flags: `--hub <url>` (default: `CLOOP_HUB_URL`, else the default
hub), and `--token <api-token>`, which replaces the stored session for scripts
and requires `--hub`. `CLOOP_API_TOKEN` isn't tied to a hub by itself. Set
together with `CLOOP_HUB_URL`, it is used for that hub only. Set alone, it is
used only for a hub this terminal has no session for. So a token exported for
one hub is never sent to another hub named with `--hub`.

**The credential file** is `$XDG_CONFIG_HOME/cloop/hubs.json`
(`~/.config/cloop/hubs.json`), mode `0600` in a `0700` directory. Every command
that would use a credential from it refuses the file if its group or other
users can read it, and no command prints a credential.
[`cloop task attach`](../operations/attach.md) uses the stored session for the
hub it targets (`--hub`, `CLOOP_HUB_URL` or the default hub) when no `--token`
is given, with the same rule for `CLOOP_API_TOKEN`.

### `cloop remote init`

Creates a hub project from the git checkout you run it in. The walkthrough is
[From a checkout to a running project](../getting-started/terminal.md#from-a-checkout-to-a-running-project).

```bash
cloop remote init --goal "Ship rate limiting for the public API"
cloop remote init --goal "…" --executor edge-01 --access write --branch 'cloop/*' --run
cloop remote init --goal "…" --repo acme/api-docs --grant staging-cluster,namespace=payments --json
```

| Flag | Default | Description |
|------|---------|-------------|
| `--goal` | asked at a terminal | What the project should achieve; required otherwise |
| `--executor` | the hub's default | Bind the project to this executor, by id or name. Its access list must admit you, and binding requires `executor.manage` |
| `--repo` | | Another repository the project works on, as `owner/name` (repeatable, or comma-separated). The origin's repository is always included |
| `--grant` | | Another stored credential to give the project: `<secret>[,key=value…]` with keys `repo`, `access`, `permission`, `branch`, `namespace`, `context`, `host`, `registry`, `env`, `scope`, `writable`, `ttl`. Repeat a key for several values |
| `--repo-secret` | chosen | The GitHub App or token the repositories are granted through |
| `--access` | `read` | `read`, or `write` (push branches and open pull requests) |
| `--branch` | | With `--access write`, limit pushes to these branches (globs) |
| `--name` | the repository's name | The project's name and its directory under the hub's projects root (`ui.projects_root`) |
| `--dir` | | The project's directory on the hub, instead of `--name`. It must be inside the hub's projects root unless you hold `executor.manage` |
| `--provider`, `--model`, `--effort` | the hub's | As the New Project dialog's |
| `--claude-secret` | your one complete Claude credential | The env secret the project's sandbox uses to sign in to Claude (for a `copilot` project, to Copilot, with `COPILOT_GITHUB_TOKEN`) on an executor that isolates |
| `--justification` | the goal | The reason given for any credential requested from an approver |
| `--run` | `false` | Start the project's first run once it is set up |
| `--json` | `false` | Print what was created, granted and requested as one object |

The origin remote can be in any of git's forms for GitHub (https, the scp form,
`ssh://`, `ssh.github.com:443`). If it is not on GitHub or contains a credential,
it is refused with an error that names the remote without printing it. Before
anything is created, the command checks the executor against your access lists,
every `--grant` secret against what you can see or request, and the hub for a
GitHub credential that can reach the repositories. The project, its binding and
the grants you may make are created in one request, which is applied completely
or not at all. A directory that already holds a project is refused (`CONFLICT`)
instead of being initialised again. Repositories are then granted through your
GitHub App installation, the organisation's if you may grant it, or your own
token if the hub's git proxy guards it; each App is asked which repositories it
can reach. What you may not grant is requested instead, and the request's id and
approvers are printed. The command exits non-zero if the project was created but
a repository can't be reached or `--run` couldn't start it.

### `cloop remote executors`

Lists the executors your projects may be bound to: every executor without an
access list, and the restricted ones whose list admits you. Each is shown with
its kind, isolation and status, with the hub's default first. For an executor
that can't run anything right now, it shows why. `--json` prints them with the
default's id.

### `cloop remote repos`

```bash
cloop remote repos list <project> [--json]
cloop remote repos add <project> <owner/name>... [--secret <name>] [--access read|write] [--branch <glob>]... [--ttl <d>] [--justification <text>] [--json]
cloop remote repos remove <project> <owner/name|grant-id>... [--json]
```

`add` chooses the credential the way `init` does, unless `--secret` names one.
It skips repositories the project can already reach, and turns a grant refused
for lack of `secret.grant` into a request (with `--justification`). `remove`,
given a repository, replaces a grant that also covers other repositories with
one that doesn't, and revokes a grant that covers only that repository. A grant
that also reaches other projects is refused, as it is in the panel.

### `cloop remote grants`

```bash
cloop remote grants request <secret> (--project <project> | --subject executor:<id>) --justification <text>
    [--repo owner/name]... [--access read|write] [--branch <glob>]... [--permission <p>]...
    [--namespace <ns>]... [--context <ctx>]... [--host <h>]... [--registry <r>]... [--env-key <K>]...
    [--writable] [--ttl <d>] [--wait <d>] [--json]
cloop remote grants list [--state pending|approved|denied|withdrawn|expired] [--mine] [--json]
cloop remote grants withdraw <request-id> [--json]
```

A request names a stored credential and the restrictions its kind requires. It
grants nothing until an approver with `secret.grant` approves it, and the
approver can never be the requester. `request` and `list` print who can approve
a pending request: the accounts and groups that the hub's role policy gives
`secret.grant` hub-wide (only administrators, for a request aimed at every
project or executor). `list` also shows how each of your requests ended:
approved and by whom, denied with the approver's reason, or lapsed without a
decision.

### `cloop remote approvals`

```bash
cloop remote approvals list [--json]
cloop remote approvals approve <id> [--ttl <d>] [--note <text>] [--json]
cloop remote approvals deny <id> --note <text> [--json]
```

What is waiting for you: the access requests you may decide and, under an
enforced role policy, the API tokens waiting for an administrator who holds
their roles. You may decide a request that somebody else filed for a subject
you hold `secret.grant` on; a request aimed at every project or executor also
requires you to be an administrator. `list` prints them nearest deadline first,
with each request's justification. It is the hub's inbox for your session, the
same one the dashboard's header badge counts (`GET /api/approvals`).

`approve` takes a whole id from the list, not a prefix, because a prefix that
names one item now could name another once that one is decided. A request is
approved as asked through `POST /api/grant-requests/{id}/approve`. `--ttl` (a
minute or more) can only shorten the grant, and the answer says when it ends. A
token is approved through `POST /api/tokens/{id}/approve`. `deny` refuses a
request with a reason the requester can read. Tokens are never denied; they are
revoked. A request id that isn't in your inbox is still sent, so that the hub
can say why you can't decide it: somebody decided it first, it is your own, or
it lapsed.

### `cloop remote features`

```bash
cloop remote features start <project> <name> [--description <text>] [--base <branch>] [--task <text>]...
    [--auto-evolve] [--innovate] [--parallel] [--max-parallel N] [--auto-pr] [--json]
cloop remote features list <project> [--json]
cloop remote features pr <project> <feature> [--title <t>] [--body <b>] [--draft] [--json]
```

A feature is a branch of the project with its own worktree and task list (see
[parallel features](../guides/features.md)). `start` prints the index the feature
runs under (`cloop remote run <index>`). `pr` pushes its branch and opens a pull
request against the branch it was created from, or reports the one already open.

### `cloop remote kube`

Share a Kubernetes cluster with the hub through a least-privilege
ServiceAccount. Use this for a cluster whose kubeconfig signs you in through an
exec credential plugin (`kubelogin`, `aws eks get-token`,
`gke-gcloud-auth-plugin`), since the hub never runs such plugins. `share` runs
the plugin on this machine, creates a labelled ServiceAccount bound to `view`
(or `edit`) in the named namespaces, mints a time-limited token through the
TokenRequest API, and stores a static kubeconfig for it on the hub as a
personal secret. See
[the secrets guide](../guides/secrets.md#a-cluster-that-signs-you-in-through-a-plugin-aks-eks-gke).

```bash
cloop remote kube share <name> --context <ctx> --namespaces a,b [--access read|write]
    [--sa-namespace <ns>] [--ttl 24h] [--renewal auto|hub|manual] [--cluster-wide]
    [--server <url>] [--kubeconfig <file>] [--shared] [--dry-run]
cloop remote kube list [--json]
cloop remote kube renew <name> [--local] [--context <ctx>] [--ttl <d>] [--kubeconfig <file>]
cloop remote kube revoke <name> [--force] [--context <ctx>] [--kubeconfig <file>]
```

| Subcommand | Calls | Permission |
|------------|-------|------------|
| `share` | the cluster as you; then `GET /api/secrets`, `POST /api/secrets` | `secret.own` (`secret.grant` with `--shared`) |
| `list` | `GET /api/secrets` | `secret.own` |
| `renew` | `POST /api/secrets/{id}/renew` with an empty body, for the hub to renew it now; or `GET /api/secrets/{id}/authorize`, the cluster as you, then the renew call with a token minted here and the server and CA it was minted at | `secret.own`, the share's owner |
| `revoke` | `GET /api/secrets/{id}/authorize`; the cluster as you; then `DELETE /api/secrets/{id}` | `secret.own`, the share's owner |

- **Write access** (`--access write`) requires `--sa-namespace`, a namespace
  outside `--namespaces`, because `edit` can mint a ServiceAccount's credential
  in its own namespace. Cluster-wide write access is refused.
- **Renewal.** With `auto`, the hub renews the token at half its lifetime if it
  runs its Kubernetes access monitor. It installs a Role that lets the
  ServiceAccount create its own token and nothing else, and the monitor refuses
  that subresource to every sandbox. Otherwise, or with `manual`, `renew` mints
  the next token with your credentials, and the hub checks it with the cluster.
- **`--ttl`** is between 10m and 7d. If the cluster caps it lower, you are told.
- **`revoke`** asks the hub first, then deletes the ServiceAccount, its
  bindings, and finally the hub's secret. In the cluster it deletes only objects
  it reads back with the share's label and its owner's annotation, by uid and
  resourceVersion. Anything else is reported and left alone. `--force` deletes
  the secret even if the cluster's objects could not be deleted.
- **The context** (`--context`, by default the one the share was made from) must
  reach the share's own API server through the CA the share trusts, or `renew`
  and `revoke` refuse to run. `renew` mints tokens only for the share's own
  ServiceAccount, read back the same way, and the hub sends the token only to
  the server that minted it.

### `cloop knowledge`

```bash
cloop knowledge sources [--json]
cloop knowledge sync <source> [--wait] [--json]
cloop knowledge search <project> <query...> [-k N] [--json]
```

Work with a hub's knowledge sources (Confluence spaces, Jira projects) from a
terminal signed in with `cloop login`, or with `--token` / `CLOOP_API_TOKEN`. As
with `cloop remote`, each subcommand makes the same API call as the dashboard,
and `--hub` names the hub. A `<source>` is an id or a name, as `sources` lists
them. A `<project>` is a name, an index or a path, as `cloop remote projects`
lists them.

| Subcommand | Calls | Permission |
|------------|-------|------------|
| `sources` | `GET /api/knowledge/sources` | `secret.own` (an administrator sees every source; anyone else the organisation's and their own) |
| `sync` | `POST /api/knowledge/sources/{id}/sync`, then with `--wait` `GET /api/knowledge/sources/{id}` until the sync ends | `knowledge.admin`, or ownership of a personal source |
| `search` | `GET /api/projects/{idx}/knowledge/search` | `project.read` on the project |

`sources` prints each source's status (`never synced`, `syncing`, `ok`,
`error`, `interrupted`, `disabled`), its documents, when it last synced and
when it is next scheduled to sync. Below the table it prints the last error of
each source that failed, with credentials removed by the hub. The hub-cluster
leader syncs every enabled source on its interval: 30 minutes, or what the
source sets between 5 minutes and 24 hours (`sync_interval_minutes`). A sync
that stopped early continues within a minute.

`sync` starts a sync now, on the hub member the request reached, and returns at
once. With `--wait` it follows the sync to the end, reports what it listed,
created, updated and removed, and exits non-zero if it failed. Only one sync of
a source runs at a time across all members. If one is already running, the hub
answers 409 with the member that runs it, and `--wait` follows that sync
instead. The request is audited as
[`knowledge.source.sync`](audit-events.md#knowledgesource).

`search` prints the best-matching chunks of the knowledge bound to the project,
at most `-k` of them (10 by default, at most 50): where each chunk is in its
source, its link, and the matching passage with the terms marked « ». With the
hub's [semantic search](configuration.md#semantic-knowledge-search-knowledgeembeddings)
on, chunks are ranked by the query's meaning as well as its words. A search that
had to rank by words alone (because the embedding endpoint is down, for
example) says why on stderr. In `--json` output, hits have a `found_by` field.

### `cloop hub grant`

Self-service access requests, and the grants they turn into. Run it on the
hub's host, or with `--workdir` set to the hub's directory.

```bash
cloop hub grant request <secret> --to project:<path> --why "…" [constraint flags] [--ttl 8h] [--wait 72h]
cloop hub grant list [--state pending|approved|denied|withdrawn|expired] [--mine] [--uses] [--grants] [--json]
cloop hub grant approve <request-id> [--ttl <d>] [--reason "…"] [--fleet-wide]
cloop hub grant deny <request-id> --reason "…" | --withdraw
cloop hub grant unguarded <grant-id> --reason "…" | --withdraw
```

- **`list`** prints the request queue, then every kubeconfig grant delivered
  without the Kubernetes access monitor because an administrator acknowledged
  it (who, when and why), and how many grants are refused because there is no
  monitor. `--grants` lists the active grants instead, with what each kubeconfig
  grant allows in practice on a hub with no monitor.
- **`unguarded`** records that a kubeconfig grant naming namespaces, or fewer
  than every verb, may be delivered on a hub that runs no monitor, where it
  would otherwise be refused. Without the monitor, its namespaces only set
  `kubectl`'s default and its verbs are not checked. `--reason` is required.
  The acknowledgement is stored on the grant, audited as
  `secret.unguarded_ack`, and shown in the Secrets panel, in `list` and in
  `cloop hub doctor`. `--withdraw` takes it back. A share that the hub renews
  can't be acknowledged.

### `cloop hub`

Control-plane transport security.

```bash
cloop hub tls-init               # self-signed cert+key for development (0600 key)
cloop hub tls-init --host cloop.example.com --days 90
cloop hub pin                    # SPKI pin of the configured certificate
cloop hub pin --cert /path/to/fullchain.pem
```

`tls-init` won't overwrite existing key material without `--force`. A new key
stops every agent pinned to the old one from connecting until it is pinned
again. See [TLS](configuration.md#tls) for the serving configuration and
[Remote executors](configuration.md#remote-executors-edge-devices) for how the
pin reaches a device.

### `cloop hub verify-image <image>`

Checks one of cloop's own images (`ghcr.io/blechschmidt/cloop`, `cloop-harness`
or `cloop-harness-copilot`) the way a hub checks it before a sandbox runs it. A
tag is resolved to the digest its registry currently serves, and cosign
verifies the digest against the identity of
`.github/workflows/publish-images.yml` on `main` or a release tag.

```bash
cloop hub verify-image ghcr.io/blechschmidt/cloop-harness:latest
cloop hub verify-image --json ghcr.io/blechschmidt/cloop-harness@sha256:…
```

The verdict is `verified`, `unsigned` (no signature at all, as for an image
published before signing began), `unverifiable` (no cosign, or the registry or
Sigstore can't be reached) or `mismatch` (signed by someone else; a hub refuses
to run it). The exit status is 0 only for `verified`. See
[Image provenance](configuration.md#image-provenance).

### `cloop hub key`

Inspect the sealing keys, and rotate them while the hub runs. Each stored
credential is sealed under its own data key (DEK), and only the DEK is sealed
under a key-encryption key (KEK). The KEK is derived from `CLOOP_SECRET_KEY`,
or is random and kept wrapped by a KMS
([`secrets.kms`](configuration.md#sealing-keys-in-a-kms-secrets)). So a
rotation rewraps sixty bytes per row and never decrypts a payload.

```bash
cloop hub key status                       # which key seals what, rotation progress, the KMS
cloop hub key list                         # keys, whether each opens, and its KMS key version
cloop hub key rotate --dry-run             # count what would move, write nothing
cloop hub key rotate                       # mint a new KEK and rewrap onto it
cloop hub key rotate --continue            # resume onto the current primary
cloop hub key rotate --retire-previous     # finish a change of root: of CLOOP_SECRET_KEY, onto or off a KMS
cloop hub key rewrap                       # follow a rotation of the KMS key
cloop hub key retire <key-id> --yes        # destroy an old key's salt or KMS ciphertext (irreversible)
```

The roots are read the way the hub reads them: `CLOOP_SECRET_KEY_FILE`, the
systemd credential `cloop-secret-key`, or `CLOOP_SECRET_KEY`, plus
`CLOOP_SECRET_KEY_PREVIOUS` (or its file or credential) during a change of root
(see [the root key](configuration.md#the-root-key-cloop_secret_key)). The KMS
comes from the `secrets` section in `config.yaml`, merged with the overlay of
the hub that `--port` names.

| Flag | Applies to | Default | Description |
|------|-----------|---------|-------------|
| `--workdir` | all | current directory | Hub directory holding `.cloop/state.db` |
| `--port` | all | `8080` | The hub whose per-instance overlay (`.cloop/config.ui-<port>.yaml`) to merge over `config.yaml` when reading `secrets.kms` |
| `--json` | `list`, `status`, `rotate`, `rewrap` | `false` | Machine-readable output |
| `--dry-run` | `rotate` | `false` | Report what would be rewrapped without writing |
| `--continue` | `rotate` | `false` | Resume onto the current primary instead of minting a new key |
| `--batch` | `rotate` | `128` | Rows read per round |
| `--retire-previous` | `rotate` | `false` | Finish a change of root. Refused until every live hub member advertises the new root as its current one and, for a new `CLOOP_SECRET_KEY`, an escrow of it is on record or, for a KMS, the KMS answers. Then it rewraps everything onto a key of the current root and retires every key of the previous one. A plain `rotate` during a change of root is refused |
| `--yes` | `retire` | `false` | Confirm irreversible destruction of the key's salt |

After the KMS key is rotated, `rewrap` wraps every KEK the current KMS holds
again, under the KMS key it now encrypts with. One row per key changes, and no
secret does. On a running hub, the cluster leader does the same within a minute
of the KMS reporting the new key. Either way, `sealing_key.kms_rewrapped` is
recorded.

You can interrupt a rotation safely, and run it against a running hub.
`retire` is a separate second step, and it refuses while any row still
references the key. The full procedure, including upgrading a hub that predates
envelope encryption and
[changing `CLOOP_SECRET_KEY` itself](../operations/runbook.md#changing-cloop_secret_key-itself),
is in the [runbook](../operations/runbook.md#key-rotation).

These subcommands write to the state database directly, not through the HTTP
API, so they need filesystem access to it, as `cloop hub token` does.

### `cloop hub ca`

Replace the hub's own certificate authority in steps, while the hub runs. Under
`tls: auto`, this CA issues the git proxy's and the Kubernetes monitor's
certificates. The full procedure, the emergency path and the cost of moving an
advertise URL are in the [runbook](../operations/runbook.md#rotating-the-hub-ca).
**Settings → Hub health** takes the same steps from the dashboard.

```bash
cloop hub ca rotate --status                        # where it stands (the default): CAs, members, runs a step waits for
cloop hub ca rotate --stage                         # mint a new CA; every new sandbox trusts both
cloop hub ca rotate --stage --name hub.example.com  # …permitting a name beside those the monitors are reached at
cloop hub ca rotate --activate                      # certificates from the new CA, once no run dispatched before the stage is running
cloop hub ca rotate --activate --force --yes        # …now, breaking those runs, named
cloop hub ca rotate --retire-previous --yes         # drop the old CA from every bundle and destroy its key
cloop hub ca rotate --abort --yes                   # destroy a staged CA that was never activated
cloop hub ca rotate --now --yes                     # emergency: replace every CA at once, end the old runs' proxy sessions
```

| Flag | Applies to | Default | Description |
|------|-----------|---------|-------------|
| `--stage`, `--activate`, `--retire-previous`, `--status`, `--now`, `--abort` | | `--status` | The step to take. Give exactly one |
| `--force` | `--activate` | `false` | Activate although runs dispatched before the stage are still running; they stop verifying the monitors and are named on the rotation |
| `--yes` | `--retire-previous`, `--now`, `--abort`, `--activate --force` | `false` | Confirm a step that destroys a key or breaks runs |
| `--name` | `--stage`, `--now` | | A name the new CA's X.509 name constraints permit, in addition to every name a certificate was issued for and the configured advertise URLs (repeatable) |
| `--no-name-constraints` | `--stage`, `--now` | `false` | Mint the new CA without name constraints |
| `--reason` | `--abort` | | Why, for the audit trail |
| `--wait` | `--activate`, `--now` | `2m` | How long to wait for every hub member to serve certificates from the new CA (`0`: do not wait) |
| `--workdir` | all | current directory | Hub directory holding `.cloop/state.db` |
| `--port` | all | `8080` | The hub whose per-instance overlay to merge over `config.yaml` when reading `secrets.kms` and the monitors' advertise URLs |
| `--json` | all | `false` | Machine-readable output |

`--activate` is refused while a run dispatched before the stage is still
running. Whatever the flags, it is also refused while a live hub member hasn't
adopted the stage or runs a build older than CA rotation. `--retire-previous` is
refused until every member serves certificates from the new CA. Like
`cloop hub key`, it writes the state database directly and notifies every
member on the cluster bus.

#### `cloop hub key escrow`

Every key-encryption key that a KMS doesn't hold is derived from
`CLOOP_SECRET_KEY`, so rotation can't help if that value is lost. An escrow file
holds it sealed under a passphrase you choose (argon2id, 64 MiB, then
AES-256-GCM). The hub records only the escrow's id and the key's fingerprint.
An escrow neither opens nor recovers keys held by a KMS: `export` and `verify`
list them as `KMS-HELD`, and only access to that KMS key recovers them.

```bash
cloop hub key escrow export --output /secure/cloop-hub.escrow   # seal the key in this environment
cloop hub key escrow verify /secure/cloop-hub.escrow            # rehearse: does it open, and open this hub?
cloop hub key escrow verify /secure/cloop-hub.escrow --record   # record it again after an older restore
cloop hub key escrow import /secure/cloop-hub.escrow            # recover it into the hub's key file
cloop hub key escrow import /secure/cloop-hub.escrow --stdout   # print CLOOP_SECRET_KEY=… instead
```

| Flag | Applies to | Default | Description |
|------|-----------|---------|-------------|
| `--output` | `export` | | Where to write the escrow file (required). A path inside a `.cloop/` directory is refused |
| `--force` | `export` | `false` | Replace an existing escrow file at `--output` |
| `--force` | `import` | `false` | Replace a different key already in the key or env file; the old file is kept as `<file>.pre-import.<UTC>` |
| `--passphrase-file` | all | the terminal | Read the passphrase from a file, or `-` for stdin. One trailing newline is stripped |
| `--record` | `verify` | `false` | Record this escrow as the hub's, once it is proven to open the hub's sealing keys |
| `--key-file` | `import` | `CLOOP_SECRET_KEY_FILE`, else `cloop-secret-key` in the hub's directory | The key file to write the key to, with mode 0600. It must not be inside `.cloop/` |
| `--env-file` | `import` | `.cloop/hub.env`, when the hub keeps its key there | The env file to put the key into instead; every other line is kept |
| `--stdout` | `import` | `false` | Print the assignment instead of writing a file |
| `--workdir` | all | current directory | Hub directory holding `.cloop/state.db` |

`export` escrows the current key. It refuses a key that doesn't open the hub's
sealing keys (together with `CLOOP_SECRET_KEY_PREVIOUS`, during a change of
root), and a passphrase shorter than 15 characters. Before it reports success,
it reads the file back and opens it. `verify` exits 1 if the file doesn't open,
or doesn't open the hub. `cloop hub doctor` reports `secret_key.escrow`: a
warning while no escrow is recorded, and a failure when the recorded escrow
holds a different key from the one in use. See the
[runbook](../operations/runbook.md#escrowing-the-sealing-key).

### `cloop db backup` and `cloop db restore`

Back up `.cloop/state.db` while it is in use, and restore a backup after
checking it.

```bash
cloop db backup                                              # .cloop/backups/state-<UTC>.db
cloop db backup --output /var/backups/cloop/state-<UTC>.db
cloop db restore <backup> --check                            # the preflight alone; writes nothing
cloop db restore <backup> --force --reason "disk failure"    # restore over a live database
```

The backup's sidecar (`<backup>.meta.json`) records the SHA-256, the sealing
keys the backup's secrets depend on, and where its audit chain ends, all sealed
under a key derived from `CLOOP_SECRET_KEY`. A restore refuses, changing
nothing, if the backup fails its integrity check, doesn't match its sidecar,
carries a seal that doesn't verify, or holds secrets that the current
`CLOOP_SECRET_KEY` can't open. It also refuses while a hub still serves the
database. A successful restore is recorded as an `audit.restored` row and a
sealed restore record that the audit checkpoints accept. A backup whose keys a
KMS holds ([`secrets.kms`](configuration.md#sealing-keys-in-a-kms-secrets))
can only be restored where that KMS answers. The preflight asks the KMS and
reports the result either way; if the KMS doesn't answer, the restore refuses
with an error naming it.

| Flag | Default | Description |
|------|---------|-------------|
| `--reason` | | Why you are restoring (required). Recorded with the restore |
| `--check` | `false` | Run the preflight only |
| `--force` | `false` | Overwrite a live database; the old file is kept as `.pre-restore.<UTC>` |
| `--skip-checksum` | `false` | Don't check the sidecar at all, for a backup whose sidecar was lost |
| `--allow-unsealed` | `false` | Accept a sidecar whose seal cannot be checked here; the digest is still checked |
| `--accept-secret-loss` | `false` | Restore although the key cannot open the backup's sealing keys; retires them, losing what they seal (recorded). Needs a `CLOOP_SECRET_KEY` |
| `--checkpoints` | `audit.checkpoints.file` | Where to look for superseded checkpoints and append the restore record |
| `--port` | `8080` | The hub whose per-instance overlay to merge over `config.yaml` when reading `secrets.kms` |

Exit codes: 0 restored and recorded, 1 refused or failed, 2 could not run, 3
restored but not fully recorded. The procedure and a drill to rehearse it are in
the [runbook](../operations/runbook.md#backup-and-restore).

### `cloop hub token static`

Manage the deprecated static `--token` / `CLOOP_UI_TOKEN`: see whether running
hubs still accept it and when it was last used, and retire it on every member
without a restart.

```bash
cloop hub token static status                     # fingerprint, held by, last used, refusals
cloop hub token static status --json              # for scripting (unused_seconds included)
cloop hub token static retire --reason "SSO is live, INC-4471"
cloop hub token static retire --fingerprint 3f9c1e7a --reason "rotated, CHG-2291"
```

| Flag | Applies to | Default | Description |
|------|-----------|---------|-------------|
| `--workdir` | all | current directory | Hub directory holding `.cloop/state.db` |
| `--json` | `status` | `false` | Machine-readable output |
| `--reason` | `retire` | | Required. Recorded with the retirement and in the audit trail |
| `--fingerprint` | `retire` | | When hubs hold several tokens, the one to retire, given as at least 8 characters of the fingerprint `status` prints |
| `--force` | `retire` | `false` | Retire it although a hub with no single sign-on and no active admin API token would be left with nobody able to administer it |

The command finds tokens without knowing their values: every hub process
holding one reports its fingerprint and last use to the control plane, and a
`CLOOP_UI_TOKEN` exported in this shell is included too. `retire` posts a
notice on the hub bus. Members refuse the token within about a second and close
the dashboard streams and sandbox terminals it opened. A member started with
`ui.cluster.exclusive` refuses it within 30 seconds. Retirement applies to one
value: deploying a new `CLOOP_UI_TOKEN` creates a new token, and the retired one
stays refused permanently. See
[Retiring the static token](../security/model.md#retiring-the-static-token).

### `cloop hub session`

List and end signed-in dashboard sessions. It works on the session table
directly, so it still works when the HTTP listener doesn't.

```bash
cloop hub session list                                     # who is signed in
cloop hub session list --identity alice@example.com        # ...for one person
cloop hub session list --json                              # for scripting
cloop hub session revoke 3f9c1e7a --reason "stolen cookie, INC-4412"
cloop hub session revoke --identity alice@example.com --reason "compromise INC-4412"
cloop hub session revoke --all --reason "rotating IdP client secret"
```

`list` shows each session's kind: `browser`, or `cli` for a terminal signed in
with [`cloop login`](#cloop-login). `--json` adds the host name a terminal
reported, as `client`. A terminal session is revoked the same way as a
browser's, and what it holds open is closed the same way.

`revoke` requires exactly one selector: an id, `--identity` or `--all`. There
is no default, because they affect very different numbers of sessions (one,
one person's, or everyone's). A revocation is announced to running hubs, which
stop accepting the session and close the dashboard streams and sandbox
terminals it opened within about a second. A hub started with
`ui.cluster.exclusive` reads no announcements. It may serve a revoked session
from its cache for up to 30 seconds, and closes what the session opened at the
next 30-second re-check after that. `cloop hub token revoke` and
`cloop hub user offboard` announce what they revoke the same way.

### `cloop hub user offboard`

End everything one identity can still do on the hub in one operation, and
destroy everything they keep there. It first resolves an email or IdP subject
to every identifier of the same person. `--dry-run` prints the set it would act
on.

```bash
cloop hub user offboard alice@example.com --dry-run
cloop hub user offboard alice@example.com --reason "left the company, HR-882"
cloop hub user offboard alice@example.com --keep-credentials --reason "legal hold LH-17"
cloop hub user offboard 'sub:8f14e45fce' --reason "contract ended" --json
```

| Flag | Meaning |
| --- | --- |
| `--reason` | Required unless `--dry-run`; written on every audit row |
| `--dry-run` | Resolve and print, change nothing |
| `--keep-credentials` | Legal hold: sever access as usual, keep their personal secrets and Claude Code homes |
| `--json` | The report, for scripting |
| `--workdir` | The hub directory, when not the current one |

In one transaction it ends their sessions, API tokens, glasses links and
project memberships, and adds a deny binding. Then it handles these, in order,
reporting each failure separately: secret leases on their projects, the grants
over their personal secrets (revoked), the secrets themselves (deleted through
the broker, sealed bytes overwritten), pending grant requests (withdrawn),
their running tasks (stopped), and their Claude Code login on every hub member
(cancelled, logged out, removed). Projects they own are reported, never
deleted. It doesn't need `CLOOP_SECRET_KEY`. If only part of it succeeds, it
exits non-zero. See the [runbook](../operations/runbook.md#somebody-leaves).

### `cloop hub user hold`

Standing legal holds. Every offboarding of a held identity (by this command,
from the dashboard, or by the identity provider over SCIM) keeps the person's
personal secrets and Claude Code homes, as `--keep-credentials` does, and
records `user.offboard_hold`.

```bash
cloop hub user hold place alice@example.com --reason "litigation LH-17"
cloop hub user hold list
cloop hub user hold release alice@example.com --reason "LH-17 closed"
```

An identity is an email or `sub:<subject>`. `--reason` is required to place or
release a hold (at least four characters to place one, since it is what the
next administrator reads). Releasing a hold destroys nothing. Run the
offboarding again to remove what the hold kept. `--json` prints the list for
scripting.

### `cloop hub scim`

SCIM 2.0 provisioning: the credential an identity provider presents to
`/scim/v2`, and what it has provisioned. See the
[guide](../guides/scim-provisioning.md).

```bash
cloop hub scim credential create entra                  # printed once
cloop hub scim credential rotate entra --grace 1h --reason "yearly rotation"
cloop hub scim credential revoke entra --reason "moving to the new tenant"
cloop hub scim credential list
cloop hub scim status                                   # credentials, directory counts, matching
```

| Command | Meaning |
| --- | --- |
| `credential create <name>` | Mint a credential. The name is the audit actor of every change the provider makes, `scim:<name>`. Accepted on `/scim/v2` only |
| `credential rotate <name\|id>` | New secret, same name and id. `--grace` keeps the old secret working for that long, at most `168h`. Without it, the old secret stops working at once |
| `credential revoke <name\|id>` | Both secrets end at once. `--reason` is required |
| `credential list` | Every credential, live and revoked, with when each was last used |
| `status` | The credentials, the match claim, and the provisioned directory: users active and suspended, groups, and the users no hub identity matches or several do |

Each takes `--workdir` and `--json`. The same operations are under
**Settings → Provisioning (SCIM)** and `/api/scim`, which require
`user.manage`.

### `cloop hub quota`

Per-identity quota overrides: a one-off limit for a single tenant. Most quota
policy belongs in `ui.quotas` in `.cloop/config.yaml`; this command edits the
exceptions.

```bash
cloop hub quota list                                       # overrides and usage
cloop hub quota set alice@example.com \
  --limit daily_cost_usd=5 --limit max_concurrent_tasks=2 \
  --reason "runaway plan INC-4413"
cloop hub quota set alice@example.com --unset max_projects --reason "back to policy"
cloop hub quota clear alice@example.com --reason "INC-4413 closed"
```

Resources are given by name, not as flags, so a resource added later needs no
CLI change: `max_projects`, `max_concurrent_tasks`,
`max_concurrent_reproductions`, `max_executors`, `max_sessions`,
`daily_token_budget`, `daily_cost_usd`.

`set` and `clear` refuse while a hub holds the control-plane lease, and point
you to `PUT /api/quotas/{identity}` instead. The enforcer loads overrides once
at startup, so a change written behind a running hub would neither take effect
nor survive the next edit from the Quotas panel.

### `cloop hub limits`

Per-project resource ceilings: how much CPU, memory and disk, and how many
processes, one project's sandboxes may be given. The fleet-wide ceiling is set
in `executors.limits` in `.cloop/config.yaml`; this command holds a single
project below it.

```bash
cloop hub limits list                                      # both ceilings, and every capped project
cloop hub limits set /srv/projects/noisy \
  --memory 2g --cpu 2 --reason "OOMing the build box"
cloop hub limits set /srv/projects/noisy --memory 0 --reason "memory cap lifted"
cloop hub limits clear /srv/projects/noisy --reason "moved to its own node"
```

`set` merges with the stored ceiling, so capping memory leaves an existing CPU
cap alone. Set a single resource to `0` to remove only that cap. Sizes use the
same format as the rest of the executor config (`512m`, `2g`, or a bare
integer, read as megabytes).

When both ceilings apply, the tighter one wins, and the project can't raise
either. A project's own `.cloop/sandbox.yaml` is only a request. A ceiling
limits it even when it asks for nothing, because an omitted key means *no
limit*, not "the default".

Unlike `hub quota`, these work while a hub is running. Ceilings are read from
the database on every dispatch, not cached at startup, so a change applies to
the next task that starts.

### `cloop hub role`

Role bindings that you can change at runtime, on top of `ui.oidc`. Use them to
demote someone in an emergency: `oidc.admin_emails` and `oidc.role_mappings`
are read at startup, so without this command, demoting a compromised
administrator means editing the config and redeploying.

```bash
cloop hub role list                                        # runtime and configured
cloop hub role list --identity alice@example.com
cloop hub role grant email bob@example.com --role maintainer --project payments --reason "INC-4414"
cloop hub role revoke email alice@example.com --reason "credential compromise INC-4412"
cloop hub role revoke email contractor@example.com --project payments --reason "scope reduction"
cloop hub role delete rb_e1be642bd28f --reason "investigation closed"
```

`revoke` writes a deny binding instead of deleting a grant, so it also works
against access that this table never granted. `delete` removes a binding row,
and is the only way to undo a deny.

The precedence between the two layers is fixed: a deny wins, and the database
overrides the config. A deny beats every other binding at every level of
specificity, including the global admin binding that `oidc.admin_emails`
produces. Bindings are re-read every 10 seconds, so changes take effect on a
running hub without a restart and need no lease.

| Flag | Applies to | Description |
|------|-----------|-------------|
| `--reason` | every mutation | Required. Recorded in the audit trail with the operating OS user |
| `--workdir` | all | Hub directory holding `.cloop/state.db` |
| `--identity` | `session list/revoke`, `role list` | Email address or IdP subject |
| `--project` / `--executor` | `role grant/revoke` | Limit the binding to one project or executor instead of applying it everywhere |
| `--json` | every `list` | Machine-readable output |

The [runbook](../operations/runbook.md#access-emergencies) has three incident
playbooks built from these commands: a stolen session, a runaway tenant and a
compromised administrator.

### `cloop project members`

Manage who besides its owner can access a project on a hub with single sign-on.
This is the command-line counterpart of the Members card on a project's
Overview. Like `cloop hub role`, it writes the hub's control-plane database
directly, so it works even when the listener doesn't. It checks no role,
because anyone who can run it can already write that database.

```bash
cloop project members list                                   # every membership on the hub
cloop project members list payments --json
cloop project members add payments bob@example.com --role operator --reason "pairing on the ledger"
cloop project members add payments bob@example.com --role viewer --reason "read-only from now on"
cloop project members add payments team:payments-devs --role operator --reason "the payments squad"
cloop project members add payments team:everyone --role viewer --reason "open to the whole hub"
cloop project members remove payments bob@example.com --reason "moved teams"
```

`<project>` is a registered project's name or its directory. A feature shares
its project's members, so a feature is refused. `<identity>` is an email,
`sub:<subject>`, or `team:<slug>` for a team (`team:everyone` is every signed-in
identity; the other teams are kept with [`cloop hub team`](#cloop-hub-team)).
`add` on an existing member changes their role. On a project somebody owns, the
role is what the member may do there; on a project nobody owns it adds to what
the hub's role mappings give. See [Project members](../security/model.md#project-members)
for both. Each change is committed together with its audit row and announced on
the hub cluster's bus, so running hub processes apply it at once and close a
removed member's open dashboards. They also re-read the table every few seconds.

| Flag | Applies to | Description |
|------|-----------|-------------|
| `--role` | `add` | `viewer` (default), `operator`, `maintainer` or `admin` |
| `--reason` | `add`, `remove` | Required. Stored with the membership and recorded in the audit trail |
| `--workdir` | all | Hub directory holding `.cloop/state.db` |
| `--json` | `list` | Machine-readable output |

### `cloop hub team`

Keep the teams projects are shared with. A team's members are the people added
to it by name, plus everyone whose ID token carries the identity-provider group
it follows (`--idp-group`) and everyone the identity provider provisioned into
the SCIM group it follows (`--scim-group`). This is the command-line counterpart
of Settings → Teams, which needs `user.manage`; like the other `cloop hub`
commands it writes the control-plane database directly and checks no role.

```bash
cloop hub team list
cloop hub team show payments-devs --json
cloop hub team create payments-devs --name "Payments" --idp-group payments-devs --reason "payments squad"
cloop hub team update payments-devs --scim-group "Payments Engineering" --reason "moved to SCIM"
cloop hub team add payments-devs dana@example.com --reason "contractor without the group"
cloop hub team remove payments-devs dana@example.com --reason "contract ended"
cloop hub team delete payments-devs --reason "squad dissolved"
```

`everyone` is built in and can't be created, changed or given people.
`update` changes only the flags you pass; an empty value (`--idp-group ""`)
clears a link. `remove` takes away a person's named membership only: somebody in
the group a team follows stays on it until the group drops them. `delete`
removes the team and every project share naming it, in one commit, and prints the
projects it unshared. Every change is committed with its audit row (`team.*`,
`via` `cli`, with your `--reason`) and announced on the hub cluster's bus, so
running hubs close the open dashboards of anybody who lost a project through it.

| Flag | Applies to | Description |
|------|-----------|-------------|
| `--name`, `--description` | `create`, `update` | How the team is shown, and what it is for |
| `--idp-group` | `create`, `update` | The ID-token group whose members are on the team |
| `--scim-group` | `create`, `update` | The provisioned group whose members are on the team |
| `--reason` | every change | Required. Recorded in the audit trail |
| `--workdir` | all | Hub directory holding `.cloop/state.db` |
| `--json` | `list`, `show` | Machine-readable output |

### `cloop hub telemetry`

Read the diagnostic trail that the dashboard and the display-glasses page
record: the gestures they received, the views they opened, the requests they
made and any errors. These front ends run where the hub can't see them; the
glasses, for example, have no console or network inspector.

```bash
cloop hub telemetry sessions                    # recent page loads, newest first
cloop hub telemetry sessions --source glasses   # just the wearable
cloop hub telemetry show <session>              # one trail, forwards, in order
cloop hub telemetry show <session> -v           # with urls, stacks and detail
cloop hub telemetry list --kind error           # recent errors across all sessions
cloop hub telemetry list --grep /api/tasks      # anything touching an endpoint
cloop hub telemetry prune --before 7d           # delete old events now
```

Start with `sessions`, to turn a report such as "a problem around ten past
four" into a session id.

| Flag | Applies to | Description |
|------|-----------|-------------|
| `--source` | `sessions`, `list` | `dashboard` or `glasses` |
| `--kind` | `list` | `error`, `rejection`, `gesture`, `view`, `fetch`, `lifecycle`, `note` |
| `--grep` | `list` | Substring of the message, url, view or detail |
| `--limit` | `sessions`, `list`, `show` | Maximum rows to read (default 200) |
| `-v` / `--verbose` | `list`, `show` | Also print url, detail, stack, user agent and build |
| `--before` | `prune` | `7d`, `48h`, `2026-01-01`, or RFC3339 |
| `--yes` | `prune` | Skip the confirmation prompt |
| `--workdir` | all | Hub directory holding `.cloop/state.db` (default: current directory) |

Run it from the hub's own directory, or point `--workdir` at it. If the command
can't find the database, it stops with an error instead of creating an empty
one, so a wrong directory doesn't look like "no telemetry recorded".

Collection is off until an operator turns it on, in **Settings → Telemetry**
in the dashboard or with `ui.telemetry.enabled: true`. So on a hub where nobody
has turned it on, an empty trail is expected. While collection is on,
credentials are removed before storage, and the table is trimmed at 50,000
rows. The Telemetry tab shows the same data and requires `audit.read`. See
[front-end telemetry](../operations/telemetry.md).

### `cloop hub audit forward`

Where the audit trail is sent as it is written, and whether it arrives. The
cluster leader does the forwarding inside `cloop ui`. These commands read the
state it leaves in the control plane, so they work whether the hub is up or
down.

```bash
cloop hub audit forward status            # each sink: backlog, lag, last error, per-chain cursors
cloop hub audit forward status --json     # the same for a monitoring script
cloop hub audit forward verify siem.jsonl # verify the chains in what a sink received
cloop hub audit prune --before 90d        # stops at the slowest sink's cursor
cloop hub audit prune --before 90d --force
```

| Flag | Applies to | Description |
|------|-----------|-------------|
| `--port` | `status` | The hub whose configuration to read; its `config.ui-<port>.yaml` overlay is merged |
| `--json` | `status`, `verify` | Emit JSON |
| `--hub` | `prune` | Hub directory whose forwarding cursors limit the prune (default: this database, and the hub it names) |
| `--force` | `prune` | Prune rows a sink hasn't acknowledged. The sink never receives them |

`status` exits 1 when a sink was refused at load, has never delivered
(including a sink no hub has started yet), or lags more than
`audit.forward.max_lag`. `verify` reads a JSON sink's file, a collector's
export, HEC events or syslog lines. It exits 2 on a gap, a fork (one id with
two hashes), a bad hash, a broken link, or a file with no forwarded record (a
CEF stream can't be verified). A repeated row is counted but not reported.
`cloop db maintain` takes `--audit-hub` and `--force-audit-prune` for the same
hold. See
[forwarding the trail off the box](../operations/runbook.md#forwarding-the-trail-off-the-box).

---

## Network egress

`cloop egress grant / list / test / revoke` issue and inspect the leases that
let an isolated sandbox reach the outside world through the control plane's
proxy; see [the secrets guide](../guides/secrets.md#egress-leases). The
subcommand below covers the other enforcement point, the packet filter.

### `cloop egress firewall`

Show the packet filter that an egress authorisation compiles to, or ask what it
would do with one address.

`cloop egress test` asks the proxy whether a connection to a URL is allowed.
That is the layer-7 answer, and it only applies to a workload that uses the
proxy. This command asks the packet filter whether a packet would leave the
sandbox, which also applies to a workload that doesn't use the proxy.

The output is the same text the driver installs, so you can diff it against
`nft list table inet cloop_sbx_<id>` on a host or `kubectl get netpol -o yaml`
in a cluster. The command changes nothing on the host; it only compiles and
prints.

| Flag | Default | Description |
|------|---------|-------------|
| `--grant` | | Compile a stored grant by ID instead of using the flags below |
| `--cidrs` | | Address ranges the sandbox may reach directly |
| `--ports` | | Destination ports; required whenever a destination is allowed |
| `--internet` | `false` | Allow every public address on `--ports` |
| `--broker` | | Egress proxy endpoint the sandbox may reach (`address:port`) |
| `--resolver` | | DNS server it may query directly (address, or `address:port`) |
| `--format` | `rules` | `rules`, `nft`, `nft-bridge` or `networkpolicy` |
| `--table` | `cloop_sbx_preview` | nft table / NetworkPolicy name |
| `--bridge` | | Host interface to filter; required by `--format nft-bridge` |
| `--check` | | Report the verdict for one `address:port` and exit 1 if denied |
| `--drop-denied` | | Render every deny as a drop, with no reply, instead of a refusal |

`--format nft` renders the form used inside the namespace (output, input and
forward chains, all defaulting to drop). `nft-bridge` renders the host-side
form, which filters one bridge. `--check` accepts an optional `/tcp` or `/udp`
suffix and defaults to TCP.

**Previewing a configuration before you write it.** The rules are printed in
evaluation order (the first match wins), each with the reason that will appear
in the ruleset and in the audit trail:

```console
$ cloop egress firewall --cidrs 10.8.0.0/24 --ports 6443 --format rules
IP-layer egress filter  mode filtered, 35 rules, from flags

  allow  127.0.0.0/8                any          sandbox-local loopback [namespace-local]
  allow  ::1/128                    any          sandbox-local loopback [namespace-local]
  deny   64:ff9b::/96               any          NAT64 translation prefix
  deny   64:ff9b:1::/48             any          NAT64 translation prefix (RFC 8215)
  deny   ::ffff:0:0:0/96            any          IPv4-translatable prefix
  deny   2002::/16                  any          6to4 translation prefix
  deny   ::/96                      any          IPv4-compatible prefix (deprecated)
  allow  10.8.0.0/24            tcp 6443         granted CIDR (waives private (RFC1918/ULA))
  deny   100.100.100.200/32         any          cloud metadata service (100.100.100.200)
  deny   168.63.129.16/32           any          cloud metadata service (168.63.129.16)
  deny   169.254.169.254/32         any          cloud metadata service (169.254.169.254)
  ...
  deny   169.254.170.23/32          any          cloud metadata service (169.254.170.23)
  deny   0.0.0.0/32                 any          unspecified address
  deny   127.0.0.0/8                any          loopback
  deny   224.0.0.0/4                any          multicast
  deny   169.254.0.0/16             any          link-local
  deny   10.0.0.0/8                 any          private (RFC1918/ULA)
  deny   172.16.0.0/12              any          private (RFC1918/ULA)
  deny   192.168.0.0/16             any          private (RFC1918/ULA)
  deny   100.64.0.0/10              any          carrier-grade NAT (RFC6598)
  deny   fd00:ec2::254/128          any          cloud metadata service (fd00:ec2::254)
  ...
  deny   ::/128                     any          unspecified address
  deny   ff00::/8                   any          multicast
  deny   fe80::/10                  any          link-local
  deny   fc00::/7                   any          private (RFC1918/ULA)
  deny   everything else                         default deny

  every deny is refused at once: a TCP reset, or an ICMP "administratively prohibited"
```

The granted `10.8.0.0/24` is allowed *before* `10.0.0.0/8` is dropped. This
ordering is how a grant waives a blocked range, and it means the grant opens
that prefix on that port and nothing else. Two kinds of drop come *before* the
granted allow, so a granted range never opens them. One is the IPv6 encodings
that carry an IPv4 address (a packet filter can't unwrap them, so it drops the
whole prefix). The other is each cloud metadata service inside the range
(`169.254.0.0/16` would contain six of them), which only the service's own
`/32` or `/128` in `--cidrs` opens.

**Seeing what a hostname allowlist turns into.** The warning appears in every
format, including as comments in the nft output:

```console
$ cloop egress firewall --internet --ports 443 --format rules
IP-layer egress filter  mode filtered, 23 rules, from flags

warning: every public address is reachable on port 443; only the private, loopback, link-local, CGNAT and metadata ranges are filtered

warning: no resolver is allowed, so DNS will fail: name lookups leave the sandbox on UDP/53 and this policy drops them. Pass the sandbox's resolvers, or use the broker, which resolves on its behalf.
```

With `--grant <id>`, a grant whose allowlist contains hostnames produces a
warning that names those hostnames and the port they widened to.

**Asking about one address with `--check`.** The verdict is printed on stdout
and also given as the exit status: 0 when the packet would leave, 1 when it
would be denied. Scripts don't need to parse the output.

```console
$ cloop egress firewall --internet --ports 443 --check 169.254.169.254:80
DENY  169.254.169.254 169.254.169.254:80/tcp — cloud metadata service (169.254.169.254)
$ echo $?
1

$ cloop egress firewall --cidrs 10.8.0.0/24 --ports 6443 --check 10.8.0.5:6443
ALLOW 10.8.0.5 10.8.0.5:6443/tcp — granted CIDR (waives private (RFC1918/ULA))
$ echo $?
0

$ cloop egress firewall --cidrs 10.8.0.0/24 --ports 6443 --check 10.8.0.5:22
DENY  10.8.0.5 10.8.0.5:22/tcp — private (RFC1918/ULA)
$ echo $?
1
```

In the third example, the address is inside the granted range but is still
dropped, because the grant covers the prefix only *on its ports*. The reason
names the rule that decided, so you can see why a sandbox can't reach an
address.

**Rendering what a host would run.** `nft-bridge` is the form the container
driver installs. Both hooks carry the same rules: `forward` for destinations
the host routes onward, and `input` for destinations on the host itself:

```console
$ cloop egress firewall --cidrs 10.8.0.0/24 --ports 6443 --resolver 10.88.0.1 \
    --format nft-bridge --bridge br-8e9671342cdf --table cloop_sbx_container
# cloop sandbox egress filter — mode filtered
# Generated by pkg/netfilter. Edits are lost on the next task.

add table inet cloop_sbx_container
delete table inet cloop_sbx_container
table inet cloop_sbx_container {
	chain deny {
		meta l4proto tcp reject with tcp reset comment "refused: connection reset"
		reject with icmpx type admin-prohibited comment "refused: administratively prohibited"
	}

	chain forward {
		type filter hook forward priority 0; policy accept;
		iifname != "br-8e9671342cdf" return comment "not this sandbox"
		ct state established,related counter accept
		ct state invalid counter drop
		ip daddr 10.88.0.1/32 udp dport 53 counter accept comment "DNS resolver"
		ip daddr 10.88.0.1/32 tcp dport 53 counter accept comment "DNS resolver (truncated answers retry over TCP)"
		ip6 daddr 64:ff9b::/96 counter jump deny comment "NAT64 translation prefix"
		…
		ip daddr 10.8.0.0/24 tcp dport 6443 counter accept comment "granted CIDR (waives private (RFC1918/ULA))"
		ip daddr 169.254.169.254/32 counter jump deny comment "cloud metadata service (169.254.169.254)"
		…
		counter jump deny comment "default deny"
	}

	chain input {
		type filter hook input priority 0; policy accept;
		…
	}
}
```

Every deny path jumps to the `deny` chain, which refuses the connection with a
TCP reset or an ICMP "administratively prohibited", so a blocked connection
fails immediately instead of timing out (`--drop-denied` renders a plain drop
instead). The chain policy is `accept` and the deny is explicit, because all
base chains on the same hook run: a `policy drop` here would cut off every
other container on the host. The driver installs the same ruleset with a
rate-limited `log … group N` statement before each deny path, which is how a
run's refusals get into its history. This preview has no group to log to, so it
leaves those statements out. Each chain returns immediately for traffic that
doesn't come from this sandbox's bridge. The `add table` / `delete table` /
`table` preamble makes a re-apply replace the table instead of adding to it
(`add` does nothing if the table exists, so the `delete` is safe on a first
run), and `nft -f` applies it all as one transaction. Every rule has a
`counter`, so `nft list table inet …` shows which rules matched when a sandbox
can't reach something; see the
[runbook](../operations/runbook.md#incident-playbooks).

See [IP-layer egress filtering](configuration.md#ip-layer-egress-filtering)
for the config keys, and [the security model](../security/model.md#the-network-the-sandbox-sits-on)
for what each layer does and doesn't enforce.

---

## Cleaning up after a killed control plane

When a hub dies during a run, its containers, Pods and edge-device processes
keep running. The next hub reattaches to the ones it can still identify and
removes the rest. These two commands clean up what is left: workloads on a
host whose hub isn't running, or on a runtime shared with a hub that will never
run again, and the part of the worktree cleanup that is too destructive to do
unattended. See [the restart sweep](../architecture/executors.md#the-restart-sweep)
for what the hub does by itself.

### `cloop executor reap <executor-id>`

Remove sandbox containers or Pods that this control plane created but no longer
tracks. It takes exactly one executor ID and works on `container` and
`kubernetes` executors; other kinds are refused.

Both backends remove terminated workloads immediately, and running ones once
they are older than that executor's
[`orphan_grace_period_seconds`](configuration.md#container-sandbox) (ten minutes
by default). Running orphans matter most: an exited container only holds a name
and a writable layer, but a running orphan keeps using a CPU core, or a node's
CPU and a ResourceQuota slot, with nobody reading its output.

The grace period makes it safe to remove running workloads. A container or Pod
that appeared moments ago may belong to a control plane that is starting up, or
to this one in the gap between starting a workload and recording its handle.
Anything older than the grace period is past both. A running container must
also carry this executor's own labels, so two container executors sharing a
host can't remove each other's work.

### `cloop worktree list` / `cloop worktree prune`

When tasks run in parallel, each gets its own git worktree under
`.cloop/worktrees/task-<id>`, on a branch named `cloop/task-<id>-<slug>`. Both
are removed when the task finishes, but a run killed before then leaves both
behind. Both commands work on the repository in the current directory.

```console
$ cloop worktree list
TASK     BRANCH                                 DIR        GIT        AGE
17       cloop/task-17-add-retry                yes        yes        3h0m0s
23       cloop/task-23-fix-parser               yes        no         26h0m0s
```

`DIR` shows whether the directory is on disk, and `GIT` whether
`git worktree list` still has it registered. If they disagree, that is a leak:
a directory with no registration is what a `git worktree prune` leaves behind,
and a registration with no directory is what an `rm -rf` leaves. Checking only
one of them would miss the other kind. `list` also prints the `cloop/task-*`
branches in the repository, which `prune` leaves alone unless you ask.

`prune` removes the directories. Start with `--dry-run`.

| Flag | Default | Description |
|------|---------|-------------|
| `--dry-run` | `false` | Report the whole plan, including branches, without changing anything |
| `--min-age` | `2h0m0s` | Only prune worktrees idle for at least this long; `0` disables the guard |
| `--delete-branches` | `false` | Also delete `cloop/task-*` branches already merged into the base |
| `--base` | the checked-out branch | Branch to check for merges against |

**`--min-age` is the only flag here that can destroy work.** The worktrees of a
parallel run in progress are in that directory, and an agent that has been
thinking for twenty minutes has written nothing in that time. The modification
time can't
tell "finished an hour ago" from "still running and quiet for an hour". Two
hours covers any likely quiet period in a running task. Only pass
`--min-age 0` once you are sure nothing is running: git can't restore work that
was never committed. A `git worktree lock` is respected whatever the age, and a
directory whose age can't be read is kept.

**`--delete-branches` can't delete unmerged work at any setting.** A branch is
deleted only if its commits are already in `--base`, and this is checked twice:
by an explicit `git for-each-ref --merged` query, and then by `git
branch -d`, which refuses an unmerged branch on its own authority. `-D` is never
used. Squash-merged branches are therefore kept and reported, because no
ancestry check can detect a squash merge.

Every entry the sweep keeps is reported with the reason. A non-zero exit means
some worktree could not be removed (a permission error, a busy mount); the
error names it, and the others were still removed.

---

## Executor pools

An executor pool is a set of runners that the executor controller starts on a
Kubernetes cluster as the pool's queued runs need them. These commands are the
Executors tab's pool section, made from a terminal: each is one of the hub's own
calls (`/api/executor-pools`), made with the session `cloop login` stored or
`--token`, and needs `executor.manage`. On a hub with single sign-on, every
change also needs a recent sign-in; run `cloop login` again when asked.

### `cloop executor pool`

```text
cloop executor pool create <name> --max-runners N [--label k=v]... [--audience user:<email>|group:<name>|role:<role>]...
    [--harness <name>]... [--owner <email>] [--namespace <ns>] [--release <name>] [--min-runners N]
    [--persistence [--size 20Gi] [--storage-class <class>] [--reclaim-policy Delete|Retain]]
cloop executor pool list
cloop executor pool show <pool>
cloop executor pool update <pool> --max-runners N [--namespace <ns>] [--release <name>]
cloop executor pool cordon <pool> [--reason <text>]
cloop executor pool uncordon <pool>
cloop executor pool rotate-credential <pool> [--finish [--force]] [--namespace <ns>] [--release <name>]
cloop executor pool revoke <pool> [--yes]
```

All take `--hub`, `--token` and `--json`. A pool is named by its name or its id.

| Command | What it does |
| --- | --- |
| `create` | Creates the pool, admits the `--audience` principals to its access list and mints its first controller credential, in one request. It prints the credential once, inside the commands that install the controller: a namespace held to the restricted Pod Security profile, a Secret holding the credential, and `helm install` of this hub's own copy of the chart (`/charts/cloop-executor-controller.tgz`) with the hub's URL and pin filled in. A hub served over plain HTTP prints the credential and says why there is no command. |
| `list` | Every live pool: the runs waiting, its busy, idle and starting runners against its maximum, its volumes, the build and protocol its controller named and when it last made contact, and how many problems the hub finds. The problems follow the table. |
| `show` | One pool in full: its runners, its queue, its controller credentials with their last use, and each problem with how to fix it. For a controller behind this hub it prints the `helm upgrade` that moves a default install forward. |
| `update` | Changes how many runners the pool may have at once on the hub, keeping the rest of its definition. The controller stops at the lower of this and its ExecutorPool's `spec.maxRunners`, so the command also prints the `helm upgrade` that changes the cluster side of a default install. |
| `cordon` / `uncordon` | A cordoned pool's runners are handed no queued run and its controller is told no demand, so it starts nothing and lets idle runners go; busy runners finish. The runs waiting for it say why. |
| `rotate-credential` | Mints a new controller credential and prints the command that puts it in the controller's Secret; the controller reads the Secret again within five minutes. `--finish` then revokes every older credential, but only once the newest has been used more recently than any older one, and while no busy runner was started with one of them (`--force` skips both checks). Revoking a credential retires the runners it started. |
| `revoke` | Revokes the pool: its controller credentials, unredeemed runner tokens and runners go with it, the leases of their runs are closed, and the runs waiting for it are cancelled. Asks first unless `--yes`. |

The problems `list` and `show` report are the ones `cloop hub doctor` reports
under `executors.pools`: runs waiting with no controller in contact, runs waiting
for ten minutes while every runner the pool may have is busy, volumes stuck
Pending, runs waiting with room for runners that the controller does not start,
and a controller that speaks an older pool-controller protocol than the hub.

## Device forwarders

A device forwarder carries one on-premises USB device or network segment to the
hub over an outbound tunnel, and a binding gives it to one project's runs. See
[the guide](../guides/device-forwarders.md) for the whole flow. Every command
except the first works on the control plane in the current directory.

### `cloop forward`

Run the forwarder on the on-premises machine: `cloop forward --bundle <bundle>`
the first time, and plain `cloop forward` after that (the credential is saved
with mode `0600` at `~/.cloop/forwarder.json`). `--usb vendor:product[:serial]`
or `--interface <name>` names the device when no bundle does.

### `cloop forward enroll` / `list` / `revoke <id>`

`enroll --name N (--usb V:P[:S] | --interface I)` mints a single-use token and
prints the `cloop forward --bundle …` command. `list` shows the forwarders.
`revoke` revokes a token or a forwarder together with its bindings, and tells
the running hubs, which end its live session and detach its device from every
run.

### `cloop forward bind <forwarder-id>` / `bindings` / `unbind <binding-id>`

`bind --project DIR [--virtual-executor ID] [--ttl 24h] [--target NAME
--address CIDR --gateway IP --mtu N] [--note TEXT]` makes the forwarder's device
available to the project's runs (only on that virtual executor, if given) for
the TTL, at most 90 days. `bindings [--project DIR] [--all]` lists the
bindings. `unbind [--reason TEXT]` revokes one and tells the running hubs,
which detach the device from any run holding it. Both are audited
(`forwarder.bind`, `forwarder.unbind`).

## Executor internals

Commands that an executor runs for you. You don't normally type them, but you
will see them in container logs and failing init containers.

### `cloop workspace provision`

Check out a git workspace into a directory, then exit. An isolated executor
runs this *before* the harness starts: in a Kubernetes init container named
`workspace`, or anywhere else the code must be in place before the workload.
The Kubernetes driver builds the arguments, so the flags below are an interface
between the driver and this command, not one meant for people.

> This is unrelated to the other `cloop workspace` subcommands (`add`, `list`,
> `switch`, …), which manage several cloop projects from one root directory.

```bash
cloop workspace provision --dir /workspace/project --repo https://github.com/acme/app.git
cloop workspace provision --dir /workspace/project --repo https://github.com/acme/app.git \
    --ref main --depth 1 --size-limit-mb 512
```

| Flag | Default | Description |
|------|---------|-------------|
| `--dir` | | Absolute directory to provision the source tree into (**required**) |
| `--repo` | | `https://` clone URL of the repository to fetch (**required**) |
| `--ref` | the remote's default branch | Branch, tag or commit to check out |
| `--depth` | `0` | Shallow-fetch depth; `0` fetches full history |
| `--size-limit-mb` | `0` | Refuse a provisioned tree larger than this many megabytes; `0` means no limit |
| `--seed` | | Place the project state in this file into the checkout as `.cloop/state.json` once it is fetched |
| `--seed-copy` | | Also leave the project state at this path, for `cloop workspace writeback --seed` (needs `--seed`) |

**The project state comes with the tree.** A clone of a source repository is
not a cloop project, so for a seeded run the Kubernetes driver puts the hub's
project state into this container (and only this one) and passes `--seed`.
After the fetch, the command writes it into the checkout, as a remote agent
does after its own fetch. It keeps `.cloop/` out of the tree's commits (with an
`info/exclude` entry, and skip-worktree on anything the repository tracks under
it), so neither the harness nor the push write-back can commit the hub's
project into the repository. If the repository commits its own `.cloop/`, the
hub's project replaces it: its database is removed from the working tree first,
and the run sees the hub's project. `--seed-copy` leaves a copy of the state
where the harness's wrapper compares the run's changes against it. See
[Kubernetes: the seed in a Secret, the outcome in the log](../architecture/executors.md#kubernetes-the-seed-in-a-secret-the-outcome-in-the-log-task-20402).

`--dir` must be absolute, because a relative path would depend on the Pod's
working directory, which the image author chooses, not the driver. The repo URL
must be `https://` and must not contain credentials;
[the workspace contract](../architecture/executors.md#workspace-provisioning)
explains why.

**Credentials come from the environment.** It is the only channel a Pod has
that is neither the command line (`/proc` shows it to every process with the
same uid) nor a file (which outlives the process that needed it):

| Variable | Meaning |
|----------|---------|
| `CLOOP_WORKSPACE_TOKEN` | the bare token; absent or empty means an unauthenticated fetch, which works for a public repository |
| `CLOOP_WORKSPACE_USER` | the basic-auth username; defaults to `x-access-token`, which is what GitHub expects alongside a PAT |

Both are read and removed from the process's environment before anything else
is started, and no output of this command can contain either: everything it
writes and every error it returns passes through the provisioner's redaction.

The steps are `git init`, `remote add origin`, `fetch`, then
`checkout --detach FETCH_HEAD`. It doesn't use `git clone`, because `clone`
can't check out a bare commit SHA. If the directory already holds a checkout of
the *same* remote, the command fetches into it. If it holds a *different*
remote, the command refuses with an error naming both URLs, because cloning
again would discard whatever is there.

To reproduce a workspace failure outside a cluster, run it by hand:

```bash
CLOOP_WORKSPACE_TOKEN=ghp_… cloop workspace provision \
    --dir /tmp/repro --repo https://github.com/acme/app.git --ref main
```

A non-zero exit means the tree isn't there. The message names the machine, the
repository and the directory, and is safe to paste into a bug report.

### `cloop workspace writeback`

Run a harness, then return what it produced from a sandbox that is removed
when the harness ends: the files it changed, as a commit on a `cloop/` branch,
and, for a seeded run, the project state it recorded. It is the harness
container's command on Kubernetes and in a container executor's feature mode,
with the harness's own command line after `--`. It passes on the harness's
output and signals, and exits with its status. As with `provision`, the driver
builds its flags.

```bash
cloop workspace writeback --dir /workspace --repo https://github.com/acme/app.git \
    --branch cloop/task-42-add-retry --base <sha> --push -- claude --print "…"
cloop workspace writeback --dir /workspace --seed /run/cloop/dispatch/seed.gz \
    --project-result-frame k-0123456789ab -- cloop run
```

| Flag | Default | Description |
|------|---------|-------------|
| `--dir` | | Absolute path of the tree (**required**) |
| `--repo` | | `https://` clone URL the tree came from; required with `--push` |
| `--branch` | | Branch to commit to; must start with `cloop/` |
| `--base` | | Full commit SHA the workspace was provisioned at |
| `--message` | | Commit message |
| `--push` | `false` | Push the branch to the origin, with the credential in `CLOOP_WORKSPACE_TOKEN` |
| `--bundle` | | Write the commits to this file instead (a sandbox with no egress) |
| `--max-bundle-bytes` | write-back limit | Refuse a bundle larger than this |
| `--seed` | | The project state the run was started with, to read its changes back against |
| `--project-result` | | Write what the run changed in `.cloop/` to this file (container feature mode) |
| `--project-result-frame` | | Print it on stdout instead, as the last thing this command prints, as a framed and checksummed block tagged with this value (Kubernetes) |
| `--place-seed` | `false` | Place `--seed` into `--dir` before the harness starts |

A delivery (`--push` or `--bundle`) is required unless the command returns only
a seeded run's project state. In that case `--repo`, `--branch`, `--base`,
`--message` and `--max-bundle-bytes` are refused, not ignored. The write-back's
report is one `##cloop-writeback-v1##` line on stdout, printed whatever
happened. The project-result frame follows it, because a Pod's log is the only
way to get it back to the hub. The driver removes the frame from the log before
the live log and the run's artifact see it, so it only shows in `kubectl logs`.

