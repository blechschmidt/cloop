# Command reference

Every `cloop` command and its flags. For conceptual documentation see the
[documentation index](../README.md); for the executor and security
configuration keys see [Configuration](configuration.md).

## Finding a command

`cloop --help` groups its commands rather than listing them flat. The nine
groups, and what belongs in each:

| Group | What is in it |
|-------|---------------|
| **Core workflow** | `init`, `run`, `status`, `log`, `goal`, `queue`, `watch`, `reset`, `clean` |
| **Plan and tasks** | `task`, `plan`, `milestone`, `sprint`, `suggest`, `scope`, and the rest of the plan-shaping commands |
| **Hub, executors and serving** | `ui`, `serve`, `hub`, `executor`, `egress`, `agent`, `daemon`, `workspace`, `session` |
| **Secrets, access and spend** | `secret`, `env`, `config`, `budget`, `cost`, `audit`, `audit-log`, `events`, `project` |
| **Insight and reporting** | `report`, `retro`, `standup`, `insights`, `metrics`, `search`, `trace`, and other read-only views |
| **AI assistants** | `ask`, `chat`, `shell`, `do`, `ai-pair`, `kb`, `memory`, `skill`, `recipe`, `flow` |
| **Providers and models** | `providers`, `profile`, `router`, `tune`, `bench`, `compare`, `cache` |
| **Integrations and delivery** | `github`, `sync`, `ci`, `release`, `pr`, `review`, `notify`, `plugin` |
| **Maintenance and diagnostics** | `doctor`, `db`, `migrate`, `compact`, `snapshot`, `upgrade`, `version` |

`cloop task` and `cloop plan` are grouped the same way — run `cloop task --help`.

Three health checks are worth knowing before anything else goes wrong:

```bash
cloop doctor            # environment, configuration, and provider reachability
cloop config validate   # validate .cloop/config.yaml and the project state
cloop hub doctor        # control-plane readiness for a hosted hub
```

### Hidden AI advisories

The single-shot `ai-*` wrappers under `cloop task` and `cloop plan` each make one
provider call and print a report. Where one can mutate the plan it does so only
behind `--apply`. Four of them have no `--apply` at all — `task ai-coach`,
`task ai-standup`, `plan ai-brief` and `plan ai-roadmap` are advisory only — and
`plan ai-roadmap` writes to `.cloop/roadmaps/` unless you pass `--no-save`.
They are hidden from the help listing so they stop crowding it, and they remain
fully callable and scriptable at the paths they always had:

```bash
cloop task ai-acceptance-criteria   cloop task ai-blocker      cloop task ai-coach
cloop task ai-complexity            cloop task ai-impact       cloop task ai-naming
cloop task ai-risk-matrix           cloop task ai-standup      cloop task ai-what-if
cloop plan ai-brief                 cloop plan ai-epic         cloop plan ai-roadmap
```

### Model calls the dashboard dispatches

The dashboard does not call a project's model itself: its Split preview,
dictation's Revise, the blocker analysis and the plan assistant run these on
the project's executor, with the caller's Claude account, and read the result
back from a framed JSON payload (`pkg/clijson`). `cloop task revise` and
`cloop plan chat` are hidden — their arguments are the hub's to build — and with
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

> Every project runs in Product Manager mode: cloop decomposes the goal into a
> visible task plan and works through it. The legacy free-form feedback loop
> (`--pm`/non-PM) was removed in Task 20067 so all changes flow through the task
> pipeline and remain auditable in the UI.

| Flag | Default | Description |
|------|---------|-------------|
| `--max-steps` | `0` (unlimited) | Max autonomous steps |
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
| `--step-timeout` | `0` (disabled) | Timeout per step (e.g. `10m`); falls back to `step_timeout` in config when unset |
| `--max-tokens` | `0` | Max output tokens per step |
| `--add-steps` | `0` | Add more steps to max before running |
| `--steps` | `0` | Run at most N steps this session (not persisted) |
| `--dry-run` | `false` | Show prompts without running |
| `--plan-only` | `false` | Decompose tasks but don't execute |
| `--retry-failed` | `false` | Retry failed tasks |
| `--replan` | `false` | Discard existing plan and re-decompose |
| `--max-failures` | `3` | PM mode: consecutive task failures before stopping |
| `--context-steps` | `3` | Recent steps to include in prompts (0 = none) |
| `--step-delay` | | Delay between steps (e.g. `5s`, `1m`) |
| `--on-complete` | | Shell command to run on goal completion (e.g. `notify-send done`) |
| `--token-budget` | `0` | Stop when cumulative tokens reach this limit (0 = unlimited) |
| `--notify` | `false` | Send OS desktop notifications on task done, task failed, and session complete |
| `--require-committed[=VALUE]` | | Set [done means committed](../guides/done-means-committed.md) for the project, then run: `committed` (the bare flag), `pushed`, or `off`. Stored with the project, like `cloop require-committed` |
| `--follow-builds[=false]` | off | Follow new builds: when a newer cloop build is deployed at the path this run was started from, adopt it at the next task boundary — same process, same live log — instead of running the old build until the run ends. Host-process runs on Linux. Stored with the project, like the Overview's *Follow New Builds* badge; see [Following new builds](configuration.md#following-new-builds) |
| `-v, --verbose` | `false` | Show full step output (no truncation) |

**Stopping:** Press `Ctrl+C` to pause gracefully. Run `cloop run` again to resume.

**A new build while it runs:** a run keeps the build it started with until it
ends — or, with `--follow-builds` or the Overview's *Adopt at next task
boundary*, until its next task boundary, where it validates the deployed binary
(`version --json`: a strictly higher `sequence`, a `schema` at least the
database's) and re-executes itself on it. Refusals are journalled
(`run_adoption`) and the run carries on. See the runbook's *Long-lived runs
after an upgrade*.

### `cloop require-committed`

Show or set **done means committed**: a task whose agent says it is done is
accepted only once the changes it made are committed — with `pushed`, also on
the upstream of the branch they are on. Paths the attempt left uncommitted (or
commits not pushed) hand the turn back, naming them, at most twice; a task that
still ends that way goes back to `pending` as an `uncommitted_work` abort, its
work left in the tree. See [Done means committed](../guides/done-means-committed.md).

```bash
cloop require-committed              # show the setting
cloop require-committed committed    # on
cloop require-committed pushed       # on, and pushed
cloop require-committed off          # off (remembers "pushed" for next time)
cloop require-committed --json
```

The setting lives in the project's state, travels to isolating executors with
it, and reaches a running `cloop run` at its next task. The dashboard sets it
with the *Done = Committed* and *…and Pushed* badges on a project's Overview.

### `cloop status`

Show current project status including provider, progress, and token usage —
and, once it has been set, what "done" requires (`Done:     only once committed
and pushed`; see `cloop require-committed`). While a run is executing, it also
says which build that run is on, against the build of the `cloop` you ran
(`Build:    running dev+g4e35bf6 (sequence 831 on main) (pid 4242), 132 builds
behind this cloop`), whether the project follows new builds (`Follow:`), and a
pending adoption request (`Adopt:`). `--json` carries the same as `run_build`,
`run_owner`, `follow_builds` and `adopt_request`.

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

Print the build: version, Go toolchain, platform, the executor protocol, and —
for a stamped build — the commit and its place on main.

```bash
cloop version
cloop version --json   # {"version","go","os","arch","protocol","min_protocol","commit","sequence","schema"}
```

`--json` is what the device installer and a run adopting a new build execute to
validate a binary before trusting it, so it has no side effects: it loads no
configuration and opens no database. `schema` is the newest state-database
migration the build embeds; a run refuses to adopt a build whose `schema` is
behind its project's database.

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

Show or update the project goal without reinitializing (preserves all steps, task plan, and settings).

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

Generate a rich progress report with task completion status, timeline, token usage, and cost estimates.

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

Manage tasks in Product Manager mode.

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
```

#### `cloop task attachments`

The files attached to a task: what its runs left in their outbox
(`.cloop/attachments/outbox/<task-id>/`, named to the agent in
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
or its name. Limits: 32 MiB a file, 100 files and 128 MiB a task, 1 GiB a
project.

### `cloop diff`

Show git changes in the current project.

```bash
cloop diff              # all uncommitted changes vs HEAD
cloop diff --stat       # summary (files changed, insertions, deletions)
cloop diff --name-only  # just the list of changed files
cloop diff --session    # diff from when the cloop session was initialized
```

`--session` is useful for reviewing everything the AI changed during this session.
It finds the last git commit that existed before `cloop init` was run, then diffs from there.

### `cloop watch`

Live-refresh the project status while `cloop run` runs in another terminal.

```bash
cloop watch              # refresh every 2s (default)
cloop watch --interval 5s
```

Shows: goal, status, provider, step/task progress, token counts, and the last step's output — automatically stopping when the session ends.

### `cloop stats`

Show aggregated session statistics.

```bash
cloop stats
```

Includes step timing (total/avg/min/max), token usage, cost estimate for known models, and task breakdown in PM mode.

### `cloop reset`

Reset progress but keep the goal and configuration.

### `cloop clean`

Remove `.cloop/` directory entirely.

A project with [features](../guides/features.md) keeps their worktrees under
`.cloop/features/`, and each can hold uncommitted work. `clean` refuses while
any exist; `cloop clean --force` removes them through git first (their
branches are kept), then the rest of `.cloop/`.

---

## Parallel features

Several lines of work on one repository at once, each a git worktree on its
own branch with its own task list and run settings. The
[features guide](../guides/features.md) explains the model; these are the
commands.

### `cloop feature new <name>`

Create a feature: a worktree at `.cloop/features/<slug>` on a new branch
`cloop/feature/<slug>`, cut from the base branch, with its own `.cloop/`
seeded from the project's provider, model, effort and instructions.

```bash
cloop feature new "Dark mode" --description "Add a dark theme and a toggle"
cloop feature new login --task "Add a login form" --task "Hash passwords" --auto-pr
cloop feature new "Search" --auto-evolve --innovate --parallel --max-parallel 3
cloop feature new hotfix --base release-2.1
```

| Flag | Meaning |
|------|---------|
| `--description` | The feature's goal (default: the name). Its first run plans tasks from it unless `--task` gave some. |
| `--task` | An initial task, in order; repeatable. |
| `--base` | Branch to cut from and propose into (default: the remote's default branch, else `main`/`master`). |
| `--auto-evolve`, `--innovate` | The feature's own evolve settings, independent of the project's. |
| `--parallel`, `--max-parallel` | Run the feature's independent tasks concurrently. |
| `--auto-pr` | Have the dashboard open the pull request when the plan completes. |
| `--json` | Machine-readable result (used by the dashboard). |

The project directory must be the top of its git repository. A feature cannot
have features.

### `cloop feature list`

The project's features: status, task progress, commits ahead of and behind the
base (`+3 -1`, with `*N` for uncommitted changes), and the pull request.
`--no-git` skips the git status. Run inside a feature, it lists its siblings.

### `cloop feature remove <name>`

Remove the feature's worktree — and with it its task list and history. Refused
while a run is in progress, or while the worktree has uncommitted changes.

```bash
cloop feature remove dark-mode                  # branch kept
cloop feature remove dark-mode --delete-branch  # deleted only if merged
cloop feature remove dark-mode --force --delete-branch  # discard and delete regardless
```

### `cloop feature pr [name]`

Push the feature's branch and open a GitHub pull request into its base. Run
again while the pull request is open, it pushes new commits and reports the
existing one; after a merge with nothing new committed, it reports the merge.

```bash
cloop feature pr dark-mode
cloop feature pr dark-mode --draft --title "Dark mode (WIP)"
cd .cloop/features/dark-mode && cloop feature pr   # the feature you are in
```

The API token is taken from `--token`, `GITHUB_TOKEN`, `GH_TOKEN`,
`github.token` in the feature's config, git's credential helpers for the
repository, `gh auth token`, then `CLOOP_GITHUB_TOKEN` — in that order, so the
hub's own token, which it passes in that variable, never displaces a project's.
`--api-url` (or `CLOOP_GITHUB_API_URL`) points it at GitHub Enterprise; a token
from the environment or a config file is only sent to github.com or that host.

### `cloop feature pr-status [name]`

Re-read the pull request from GitHub and record whether it is open, closed or
merged.

---

## Product Manager Mode

cloop decomposes the goal into a structured task plan, then executes each task
one at a time. This is the only mode, so there is no `--pm` flag to turn it on:
it was removed in Task 20067 along with the free-form loop it selected between.

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

The AI signals task outcomes with terminal keywords:
- `TASK_DONE` — task completed successfully
- `TASK_SKIPPED` — task not applicable / already done
- `TASK_FAILED` — task could not be completed

Tasks can declare dependencies on other tasks via `depends_on` in the JSON plan.
A task will not start until all its dependencies are `done` or `skipped`.
If a dependency fails, all tasks that depend on it are automatically skipped.

---

## Analysis & Forecasting

### `cloop scope [goal]`

AI-powered project scope analysis before you start. Estimates task count, complexity, risks, prerequisites, and recommends the best execution mode.

```bash
cloop scope "Build a REST API with auth"
cloop scope                           # analyze current project goal
cloop scope --provider anthropic "Add OAuth support"
```

Output: task count estimate, complexity (low/medium/high/very_high), estimated AI invocations, risks, prerequisites, assumptions, and recommended execution mode.

### `cloop forecast`

AI-powered completion forecast with optimistic, expected, and pessimistic scenarios. Renders an ASCII burn-down chart and streams an AI narrative about delivery outlook and acceleration opportunities.

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

AI-powered project health analysis: task velocity, risk score, bottlenecks, role breakdowns, and AI-generated recommendations.

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

AI-powered sprint retrospective: what went well, what went wrong, bottlenecks, velocity notes, key insights, and recommended next actions.

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

Generate an AI-powered daily standup report: what was accomplished, what's planned next, blockers, and delivery forecast. Can post to Slack via webhook.

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

AI-generated prioritized product backlog from your codebase. Surfaces the highest-value improvements ranked by impact-to-effort ratio.

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
| `--as-tasks` | `false` | Add backlog items to the PM task plan |
| `--max-items` | `0` (all) | Maximum number of items to show/add |
| `--provider` | from config | Provider to use |
| `--model` | from config | Model override |

### `cloop prioritize`

AI-powered smart task reprioritization. Analyzes the current plan and suggests the optimal execution order based on the critical path, dependencies, risk factors, and value delivery.

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

Brainstorm feature ideas for the project, or break a request of your own into a plan of tasks. Each proposal is reviewed interactively, and the accepted ones become PM tasks. The dashboard's **AI Feature Suggestions** panel on the Tasks tab runs the same command, and so does **Decompose** beside Add Task, which plans the task typed there and gives every task of the plan the priority and dependencies typed with it.

```bash
cloop suggest                                      # brainstorm 5 ideas
cloop suggest --count 10                           # brainstorm 10 ideas
cloop suggest --input "add OAuth login"            # plan it in as many tasks as it needs
cloop suggest --input "add OAuth login" --count 4  # plan it in exactly 4 tasks
cloop suggest --yes                                # accept everything proposed
```

With `--input`, the proposals are the ordered tasks of one plan, each naming the earlier tasks it depends on. `--count` then sets the plan's length, up to 20; leave it out and the plan is as long as the request needs — a small request may be a single task. Accepted tasks join the end of the run queue in plan order and keep their dependencies on each other, through any task you reject: if task 3 needs task 2 and task 2 needs task 1, rejecting task 2 makes task 3 wait for task 1.

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

Sprint and release planning. Organize PM tasks into milestones with deadlines and velocity-based forecasting.

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

AI what-if scenario analysis: simulate hypothetical changes before committing. Projects the impact on timeline, risk, and task priorities.

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

AI-powered code review for git diffs. Returns a quality score, issues by severity, praise, and suggestions.

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
| `--task` | `0` | Include PM task context in review (task ID) |
| `--format` | `terminal` | Output format: `terminal` or `md` |
| `-o, --output` | | Write output to file |
| `--quick` | `false` | Show diff stats only, no AI call |
| `--timeout` | | Review timeout (e.g. `60s`, `2m`) |
| `--provider` | from config | Provider to use |
| `--model` | from config | Model override |

Issues are graded as: `critical`, `major`, `minor`, `suggestion`.

### `cloop review gate`

Show or configure the project's review gate: a reviewer model — its own
provider and model — that checks each task's changes before they are pushed or
merged. The agent's pushes are held until the reviewer approves. See
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

Ask the AI anything about your project state, tasks, progress, or blockers. The AI has full context: goal, task plan, recent activity, and project memory.

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

Interactive conversational AI product manager. Ask questions, get suggestions, or let the AI update your task plan — all through natural conversation.

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

The AI can take PM actions on your behalf: mark tasks done, create new tasks, and add notes to project memory.

| Flag | Default | Description |
|------|---------|-------------|
| `--provider` | from config | AI provider |
| `--model` | from config | Model override |
| `--timeout` | `120s` | Response timeout |
| `--save` | `false` | Auto-save transcript on exit |

### `cloop compare [prompt]`

Benchmark the same prompt across multiple AI providers simultaneously. Compare response quality, latency, token counts, and cost side-by-side.

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
| `--task` | `0` | Use prompt from PM task #N |
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

The repo is auto-detected from the `origin` git remote if not configured. GitHub token is also read from `GITHUB_TOKEN` env var.

### `cloop agent`

Autonomous background agent: executes PM tasks without supervision at a regular interval.

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

The agent executes one PM task per interval, records results, and stores a running state in `.cloop/agent-state.json`. Logs are written to `.cloop/agent.log`.

---

## Project Memory

### `cloop memory`

Manage the project's persistent memory stored in `.cloop/memory.json`. Memory entries are key learnings that are injected into future session prompts.

```bash
cloop memory list                      # list all stored memory entries
cloop memory add "Always use chi router, not net/http"  # add a manual entry
cloop memory delete <id>               # delete a specific entry by ID
cloop memory clear                     # delete all memory entries
```

Memory entries can be created automatically via:
- `cloop retro --save-memory` — saves retro insights to memory
- `cloop chat` — the AI can add notes via natural conversation

### `cloop checkpoint`

Save, restore, or list named snapshots of the project state. Useful before risky changes or experiments.

```bash
cloop checkpoint save before-deploy    # save a named checkpoint
cloop checkpoint save                  # save with auto-generated timestamp name
cloop checkpoint list                  # list all saved checkpoints
cloop checkpoint restore before-deploy # restore (current state auto-backed up)
cloop checkpoint delete before-deploy  # delete a checkpoint
```

Checkpoints are stored as `.json` files in `.cloop/checkpoints/`. Restoring a checkpoint automatically backs up the current state first.

---

## MCP Server (Model Context Protocol)

### `cloop mcp`

Start cloop as an MCP server, exposing it as a set of tools to Claude Desktop, Cursor, Zed, and any other client that supports the [Model Context Protocol](https://modelcontextprotocol.io/specification).

The server speaks JSON-RPC 2.0 over newline-delimited stdio. All log output goes to stderr so it does not corrupt the MCP stream.

```bash
cloop mcp                          # use the configured/auto-detected provider
cloop mcp --provider anthropic     # force a specific provider
cloop mcp --provider openai --model gpt-4o
```

#### Available MCP Tools

| Tool | Description |
|------|-------------|
| `get_status` | Return current orchestrator state: goal, status, step counts, provider |
| `get_plan` | Return the full PM-mode task plan as JSON with all task details |
| `add_task` | Append a new task to the current plan (title, description, priority) |
| `complete_task` | Mark a task done by ID with an optional result summary |
| `run_task` | Execute a one-shot AI prompt using the configured provider |

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

Once configured, Claude Desktop will offer the cloop tools in any conversation. You can ask Claude to check the plan status, add tasks, or run one-off AI prompts directly through cloop's provider.

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

Start a web dashboard with real-time updates over a WebSocket (`/api/ws`),
falling back to SSE where a WebSocket cannot be established.

It authenticates nothing unless a token or OIDC is configured, and so,
without either, listens on `127.0.0.1` only; with one it listens on every
interface. `--listen` names an address instead, and an address beyond loopback
is refused on a hub without sign-in unless `ui.allow_unauthenticated_network`
is set — see [Web UI](configuration.md#web-ui-cloop-ui) before exposing it.

```bash
cloop ui                    # start on default port 8080
cloop ui --port 9090        # use a custom port
cloop ui --no-browser       # don't open the browser automatically
cloop ui --listen 0.0.0.0   # every interface — needs sign-in (ui.oidc or CLOOP_UI_TOKEN)
```

The dashboard shows: project goal, status, step history with outputs, task list (PM mode), live progress, and run/stop controls.

| Flag | Default | Description |
|------|---------|-------------|
| `--port` | `8080` | Port to listen on |
| `--listen` | `127.0.0.1` without sign-in, every interface with it | Address to listen on, without the port (overrides `ui.listen`) |
| `--no-browser` | `false` | Do not open the browser automatically |
| `--advertise-url` | `http(s)://127.0.0.1:<port>`, or the bound address when `--listen` names one interface | Where the other hubs serving this directory reach this one (also `CLOOP_CLUSTER_ADVERTISE_URL`, or `CLOOP_CLUSTER_ADVERTISE_HOST` for the host alone) |

Several `cloop ui` in one directory serve it together, as members of one
[hub cluster](../architecture/hub-cluster.md) behind a load balancer:

```bash
cloop ui --port 8080 --no-browser &
cloop ui --port 8081 --no-browser &
cloop hub cluster status     # the members, the leader, and where each is reached
```

`cloop hub cluster status [--json]` reads the database directly, so it also
answers while every member is down, and lists members that stopped within the
last day as gone.

## Working with a hub from a terminal

A terminal signs in to a hub with single sign-on by device authorization and
then works with its projects as the person who approved it. The walkthrough is
[Working from a terminal](../getting-started/terminal.md); this is the
reference.

### `cloop login <hub-url>`

Signs this terminal in. It prints a code and the hub's approval page; a browser
signed in to the hub approves the code there (after a fresh sign-in at the
identity provider when its own is older than
`ui.oidc.device_approval_max_age_minutes`), and the terminal gets a **CLI
session** — a session of kind `cli` in the hub's store, on clocks never longer
than a browser session's, re-checked with the identity provider on the same
rule, listed and revoked like any session, ended by offboarding.

```bash
cloop login https://cloop.example.com
cloop login https://cloop.internal --ca-file /etc/ssl/internal-ca.pem
cloop login https://cloop.example.com --no-browser --hostname build-box-7
```

| Flag | Default | Description |
|------|---------|-------------|
| `--ca-file` | — | PEM bundle to trust for the hub's certificate; kept with the session |
| `--no-browser` | `false` | Print the approval link without opening a browser (one is opened only on a desktop session) |
| `--default` | `false` | Make this hub the default; the first hub signed in to already is |
| `--hostname` | the host name | What the approval page calls this machine |

The terminal generates its session credential before asking for a code and
sends the hub only its SHA-256; the approval writes the session under that
digest, and the hub's answer to the terminal's poll carries the session's id and
no secret. `cloop login` checks that id is its own digest and refuses anything
else. A session this terminal already held for the hub is ended there when the
new one replaces it.

Exits non-zero when the code is denied (`the sign-in was denied`), expires
(`the code expired before it was approved`), or the hub has no single sign-on or
has terminal sign-in turned off (`ui.oidc.device_login: false`).

### `cloop logout [hub-url]`

Ends this terminal's session **at the hub**, then deletes it from the credential
file. Without a URL it signs out of the default hub.

| Flag | Description |
|------|-------------|
| `--all` | Every hub this terminal is signed in to. Also reads a credential file other users can read — to revoke what may have been copied — which every other command refuses, `logout` of a single hub included: it would write the other hubs' credentials back into a file that looks private again |
| `--force` | Delete the credentials even if the hub cannot be reached to end the session (which then stays valid there until it expires or is revoked from the dashboard) |

A session the hub had already ended — revoked, expired, idle — is forgotten
without complaint. The credential file is removed once it holds no hub.

### `cloop whoami [hub-url]`

Asks the hub who this terminal's session is: identity, session kind and host
name, role, hub-wide permissions, and how long the session has left. `--json`
prints the hub's `/api/me` answer with the hub URL and session id added. Exits
non-zero, saying so, when the session has ended.

### `cloop remote`

The projects on a hub, as the signed-in identity. Every subcommand is one of the
dashboard's own calls, so the hub authorises it exactly as it would the
dashboard's button. A `<project>` is a name, an index or a path, as `cloop
remote projects` lists them; an ambiguous name is refused with the candidates.

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
| `repos add` | `GET /api/projects/{idx}/repositories` and `/repositories/available`, then `POST /api/projects/{idx}/repositories` — or `POST /api/grant-requests` where the grant is refused for want of `secret.grant` | `secret.grant` on the project, else `secret.request` |
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

**A refusal is rendered, not dumped.** The hub's message and code come first,
then each detail it sent as a line; for a missing permission, the permission and
the scope it was decided at, your role there, and how to get it — from a
maintainer of the project (its Members card) or an administrator (the role
mappings), or for `secret.grant` by filing a request. A refusal whose claims
were merely too old says to sign in again with `cloop login`.

`logs --follow` prints the run's output from the backlog the hub replays on
connect onwards, notes on stderr when the run starts and stops, and runs until
`Ctrl-C` — or until the hub closes the stream because the session ended or
access to the project was withdrawn, which exits non-zero with the hub's reason.

Persistent flags: `--hub <url>` (default: `CLOOP_HUB_URL`, else the default
hub), and `--token <api-token>`, which replaces the stored session for scripts
and needs `--hub`. `CLOOP_API_TOKEN` names no hub of its own: set beside
`CLOOP_HUB_URL` it is that hub's token and no other's; set alone it is used only
for a hub this terminal holds no session for — so a token exported for one hub
is never sent to another named with `--hub`.

**The credential file** is `$XDG_CONFIG_HOME/cloop/hubs.json`
(`~/.config/cloop/hubs.json`), mode `0600` in a `0700` directory. Every command
that would present a credential from it refuses a file its group or anybody
else can read, and nothing prints a credential. [`cloop task attach`](../operations/attach.md)
uses the stored session for the hub it targets — `--hub`, `CLOOP_HUB_URL` or the
default hub — when no `--token` is given, on the same rule for
`CLOOP_API_TOKEN`.

### `cloop remote init`

Creates a hub project from the git checkout it is run in (Task 20417). The
walkthrough is [From a checkout to a running project](../getting-started/terminal.md#from-a-checkout-to-a-running-project).

```bash
cloop remote init --goal "Ship rate limiting for the public API"
cloop remote init --goal "…" --executor edge-01 --access write --branch 'cloop/*' --run
cloop remote init --goal "…" --repo acme/api-docs --grant staging-cluster,namespace=payments --json
```

| Flag | Default | Description |
|------|---------|-------------|
| `--goal` | asked at a terminal | What the project should achieve; required otherwise |
| `--executor` | the hub's default | Bind the project to this executor, by id or name — one whose access list admits you. Binding takes `executor.manage` |
| `--repo` | — | Another repository the project works on, as `owner/name` (repeatable, or comma-separated); the origin's is always included |
| `--grant` | — | Another stored credential to give the project: `<secret>[,key=value…]` with keys `repo`, `access`, `permission`, `branch`, `namespace`, `context`, `host`, `registry`, `env`, `scope`, `writable`, `ttl`; repeat a key for several values |
| `--repo-secret` | chosen | The GitHub App or token the repositories are granted through |
| `--access` | `read` | `read`, or `write` (push branches and open pull requests) |
| `--branch` | — | With `--access write`, limit pushes to these branches (globs) |
| `--name` | the repository's name | The project's name and its directory under the hub's projects root (`ui.projects_root`) |
| `--dir` | — | The project's directory on the hub, instead of `--name`; inside the hub's projects root unless you hold `executor.manage` |
| `--provider`, `--model`, `--effort` | the hub's | As the New Project dialog's |
| `--claude-secret` | your one complete Claude credential | The env secret the project's sandbox signs in to Claude with — or, for a `copilot` project, to Copilot with (`COPILOT_GITHUB_TOKEN`) — on an executor that isolates |
| `--justification` | the goal | The reason given for any credential requested from an approver |
| `--run` | `false` | Start the project's first run once it is set up |
| `--json` | `false` | Print what was created, granted and requested as one object |

The origin remote is read in any of git's forms for GitHub — https, the scp form,
`ssh://`, `ssh.github.com:443` — and refused, by name and without echoing it, when
it is not on GitHub or embeds a credential. Before anything is created the executor
is checked against your access lists, every `--grant` secret against what you can
see or ask for, and the hub for some GitHub credential that could reach the
repositories. The project is created with its binding and the grants you may make
in one request, applied whole or not at all; a directory that already holds a
project is refused (`CONFLICT`) rather than initialised again. Repositories are then
granted through your GitHub App installation, the organisation's where you may grant
it, or your own token where the hub's git proxy guards it — each App asked which
repositories it reaches. What you may not grant is requested instead, and the
request's id and approvers are printed. Exits non-zero when the project was created
but a repository is unreached or `--run` could not start it.

### `cloop remote executors`

Lists the executors a project of yours may be bound to: every executor without an
access list, and the restricted ones whose list admits you — each with its kind,
isolation and status, the hub's default first, and why one that cannot run anything
now cannot. `--json` prints them with the default's id.

### `cloop remote repos`

```bash
cloop remote repos list <project> [--json]
cloop remote repos add <project> <owner/name>... [--secret <name>] [--access read|write] [--branch <glob>]... [--ttl <d>] [--justification <text>] [--json]
cloop remote repos remove <project> <owner/name|grant-id>... [--json]
```

`add` chooses the credential as `init` does unless `--secret` names one, leaves a
repository the project already reaches alone, and turns a grant refused for want of
`secret.grant` into a request (with `--justification`). `remove` by repository
replaces a grant that covers others with one that does not, and revokes one that
covers only it; a grant that reaches other projects too is refused, as the panel
refuses it.

### `cloop remote grants`

```bash
cloop remote grants request <secret> (--project <project> | --subject executor:<id>) --justification <text>
    [--repo owner/name]... [--access read|write] [--branch <glob>]... [--permission <p>]...
    [--namespace <ns>]... [--context <ctx>]... [--host <h>]... [--registry <r>]... [--env-key <K>]...
    [--writable] [--ttl <d>] [--wait <d>] [--json]
cloop remote grants list [--state pending|approved|denied|withdrawn|expired] [--mine] [--json]
cloop remote grants withdraw <request-id> [--json]
```

A request names a stored credential and the narrowing its kind needs; asking
confers nothing until an approver with `secret.grant` — never the requester —
approves it. `request` and `list` print who can approve a pending request: the
accounts and groups the hub's role policy gives `secret.grant` hub-wide (only
administrators for a request aimed at every project or executor). `list` also
says how each of yours ended: approved and by whom, denied with the approver's
reason, or lapsed undecided.

### `cloop remote approvals`

```bash
cloop remote approvals list [--json]
cloop remote approvals approve <id> [--ttl <d>] [--note <text>] [--json]
cloop remote approvals deny <id> --note <text> [--json]
```

What waits on you (Task 20427): the access requests you may decide — filed by
somebody else, for a subject you hold `secret.grant` on, and aimed at every
project or executor only if you are an administrator — and, under an enforced
role policy, the API tokens awaiting an administrator holding their roles.
`list` prints them soonest deadline first, with each request's justification;
the inbox is the hub's answer for your session, the same one the dashboard's
header badge counts (`GET /api/approvals`). `approve` takes an id from the list,
whole — a prefix that names one item when you list could name another once that
one is decided: a request is approved as asked — `--ttl`, a minute or more, can
only shorten the grant, and the answer says until when it runs — through
`POST /api/grant-requests/{id}/approve`, a token through
`POST /api/tokens/{id}/approve`. `deny` refuses a request with the
reason its requester reads; a token is never denied, it is revoked. A request
id that is not in your inbox is still sent, so the hub says why it may not be
decided — somebody decided it first, it is your own, it lapsed.

### `cloop remote features`

```bash
cloop remote features start <project> <name> [--description <text>] [--base <branch>] [--task <text>]...
    [--auto-evolve] [--innovate] [--parallel] [--max-parallel N] [--auto-pr] [--json]
cloop remote features list <project> [--json]
cloop remote features pr <project> <feature> [--title <t>] [--body <b>] [--draft] [--json]
```

A feature is a branch of the project with its own worktree and task list
([parallel features](../guides/features.md)); `start` prints the index it runs under
(`cloop remote run <index>`), and `pr` pushes its branch and opens its pull request
into the branch it was cut from, or reports the one already open.

### `cloop remote kube`

Share a Kubernetes cluster with the hub through a least-privilege ServiceAccount
(Task 20416) — the path for a cluster whose kubeconfig signs you in through an
exec credential plugin (`kubelogin`, `aws eks get-token`,
`gke-gcloud-auth-plugin`), which the hub never runs. `share` runs the plugin on
this machine, creates a labelled ServiceAccount bound to `view` (or `edit`) in
the named namespaces, mints a bounded token through the TokenRequest API, and
stores a static kubeconfig for it on the hub as a personal secret. See
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
| `renew` | `POST /api/secrets/{id}/renew` — empty for the hub to renew it now; or `GET /api/secrets/{id}/authorize`, the cluster as you, then the renew with a token minted here and the server and CA it was minted at | `secret.own`, the share's owner |
| `revoke` | `GET /api/secrets/{id}/authorize`; the cluster as you; then `DELETE /api/secrets/{id}` | `secret.own`, the share's owner |

- **Write access** (`--access write`) needs `--sa-namespace`, a namespace outside
  `--namespaces`: `edit` can mint a ServiceAccount's credential in its own
  namespace. Cluster-wide write is refused.
- **Renewal.** `auto` lets the hub renew the token at half its life when the hub
  runs its Kubernetes access monitor, installing a Role that lets the
  ServiceAccount create its own token and nothing else; the monitor refuses that
  subresource to every sandbox. Elsewhere, or with `manual`, `renew` mints the next
  token with your credentials and the hub checks it with the cluster.
- **`--ttl`** is 10m to 7d; a cluster that caps it is reported.
- **`revoke`** asks the hub first, then deletes the ServiceAccount, then its
  bindings, then the hub's secret — and in the cluster only objects it reads
  back with the share's label and its owner's annotation, by uid and
  resourceVersion; the rest are reported and left (Task 20420). `--force`
  deletes the secret even when the cluster's objects could not be.
- **The context** (`--context`, by default the one the share was made from) must
  reach the share's own API server through the CA the share trusts, or `renew`
  and `revoke` refuse. `renew` mints only for the share's own ServiceAccount, read
  back the same way, and the hub sends the token only to the server that minted
  it.

### `cloop hub grant`

Self-service access requests, and the grants they become (Task 20271). Run on the
hub's host, or with `--workdir` naming the hub's directory.

```bash
cloop hub grant request <secret> --to project:<path> --why "…" [constraint flags] [--ttl 8h] [--wait 72h]
cloop hub grant list [--state pending|approved|denied|withdrawn|expired] [--mine] [--uses] [--grants] [--json]
cloop hub grant approve <request-id> [--ttl <d>] [--reason "…"] [--fleet-wide]
cloop hub grant deny <request-id> --reason "…" | --withdraw
cloop hub grant unguarded <grant-id> --reason "…" | --withdraw
```

- **`list`** prints the request queue, then every kubeconfig grant delivered
  without the Kubernetes access monitor on an administrator's acknowledgement —
  who, when, why — and how many are refused for want of the monitor. `--grants`
  lists the active grants instead, with what each kubeconfig grant amounts to on
  a hub with no monitor.
- **`unguarded`** (Task 20420) records that a kubeconfig grant naming namespaces,
  or fewer than every verb, may be delivered on a hub that runs no monitor, where
  it is otherwise refused: its namespaces become only `kubectl`'s default and its
  verbs go unchecked. `--reason` is required; the acknowledgement is stored on
  the grant, audited as `secret.unguarded_ack`, and shown in the Secrets panel,
  `list` and `cloop hub doctor`. `--withdraw` takes it back. A share the hub
  renews cannot be acknowledged.

### `cloop hub`

Control-plane transport security.

```bash
cloop hub tls-init               # self-signed cert+key for development (0600 key)
cloop hub tls-init --host cloop.example.com --days 90
cloop hub pin                    # SPKI pin of the configured certificate
cloop hub pin --cert /path/to/fullchain.pem
```

`tls-init` refuses to overwrite existing key material without `--force`:
regenerating changes the hub's key, and every agent pinned to the old one stops
connecting until it is re-pinned. See [TLS](configuration.md#tls) for the serving configuration
and [Remote executors](configuration.md#remote-executors-edge-devices) for how the pin reaches
a device.

### `cloop hub verify-image <image>`

Checks one of cloop's own images — `ghcr.io/blechschmidt/cloop`, `cloop-harness`
or `cloop-harness-copilot` — as a hub checks it before a sandbox runs it (Task
20453): a tag is resolved to the digest its registry serves now, and cosign
verifies the digest against the identity of `.github/workflows/publish-images.yml`
on `main` or a release tag.

```bash
cloop hub verify-image ghcr.io/blechschmidt/cloop-harness:latest
cloop hub verify-image --json ghcr.io/blechschmidt/cloop-harness@sha256:…
```

The verdict is `verified`, `unsigned` (no signature at all — an image published
before signing began), `unverifiable` (no cosign, or the registry or Sigstore out
of reach) or `mismatch` (signed by someone else, which a hub refuses to run). The
exit status is 0 only for `verified`. See [Image provenance](configuration.md#image-provenance).

### `cloop hub key`

Sealing-key inspection and online rotation. Stored credentials are sealed under
a per-row data key (DEK); only the DEK is sealed under a key-encryption key
(KEK) — derived from `CLOOP_SECRET_KEY`, or random and held wrapped by a KMS
([`secrets.kms`](configuration.md#sealing-keys-in-a-kms-secrets)) — so rotating
rewraps sixty bytes per row and never decrypts a payload.

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

The roots are read as the hub reads them: `CLOOP_SECRET_KEY_FILE`, the systemd
credential `cloop-secret-key`, or `CLOOP_SECRET_KEY`, with
`CLOOP_SECRET_KEY_PREVIOUS` (or its file or credential) beside it during a change
of root — see [the root key](configuration.md#the-root-key-cloop_secret_key) —
and the KMS of the `secrets` section in `config.yaml`, with the overlay of the
hub `--port` names merged.

| Flag | Applies to | Default | Description |
|------|-----------|---------|-------------|
| `--workdir` | all | current directory | Hub directory holding `.cloop/state.db` |
| `--port` | all | `8080` | The hub whose per-instance overlay (`.cloop/config.ui-<port>.yaml`) to merge over `config.yaml` when reading `secrets.kms` |
| `--json` | `list`, `status`, `rotate`, `rewrap` | `false` | Machine-readable output |
| `--dry-run` | `rotate` | `false` | Report what would be rewrapped without writing |
| `--continue` | `rotate` | `false` | Resume onto the current primary instead of minting a new key |
| `--batch` | `rotate` | `128` | Rows read per round |
| `--retire-previous` | `rotate` | `false` | Finish a change of root: refuses until every live hub member advertises the new root as its current one and — for a new `CLOOP_SECRET_KEY` — an escrow of it is on record, or — for a KMS — the KMS answers; then rewraps everything onto a key of the current root and retires every key of the previous one. A plain `rotate` mid-change is refused |
| `--yes` | `retire` | `false` | Confirm irreversible destruction of the key's salt |

`rewrap` wraps every KEK the current KMS holds again under the KMS key it now
encrypts under, after a rotation of the KMS key; one row per key changes and no
secret does. A serving hub's cluster leader does the same within a minute of the
KMS reporting the new key, and records `sealing_key.kms_rewrapped` either way.

Rotation is safe to interrupt and safe to run against a serving hub; `retire` is
a deliberate second step and refuses while any row still references the key. The
full procedure, including upgrading a hub that predates envelope encryption and
[changing `CLOOP_SECRET_KEY` itself](../operations/runbook.md#changing-cloop_secret_key-itself),
is in the [runbook](../operations/runbook.md#key-rotation).

These subcommands write to the state database directly rather than through the
HTTP API, so they require filesystem access to it — the same root-shell caveat
as `cloop hub token`.

### `cloop hub ca`

The hub's own certificate authority — the one its git proxy's and Kubernetes
monitor's certificates come from under `tls: auto` — replaced online, in steps
(Task 20438). The full procedure, the emergency path and what moving an advertise
URL costs are in the [runbook](../operations/runbook.md#rotating-the-hub-ca);
Settings → Hub health takes the same steps from the dashboard.

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
| `--stage`, `--activate`, `--retire-previous`, `--status`, `--now`, `--abort` | — | `--status` | The step; exactly one |
| `--force` | `--activate` | `false` | Activate although runs dispatched before the stage are still running; they stop verifying the monitors and are named on the rotation |
| `--yes` | `--retire-previous`, `--now`, `--abort`, `--activate --force` | `false` | Confirm a step that destroys a key or breaks runs |
| `--name` | `--stage`, `--now` | — | A name the new CA's X.509 name constraints permit, beside every name a certificate was issued for and the configured advertise URLs (repeatable) |
| `--no-name-constraints` | `--stage`, `--now` | `false` | Mint the new CA without name constraints |
| `--reason` | `--abort` | — | Why, for the audit trail |
| `--wait` | `--activate`, `--now` | `2m` | How long to wait for every hub member to serve certificates from the new CA (`0`: do not wait) |
| `--workdir` | all | current directory | Hub directory holding `.cloop/state.db` |
| `--port` | all | `8080` | The hub whose per-instance overlay to merge over `config.yaml` when reading `secrets.kms` and the monitors' advertise URLs |
| `--json` | all | `false` | Machine-readable output |

`--activate` is refused while a run dispatched before the stage is still
running, and — whatever the flags — while a live hub member has not adopted the
stage or runs a build that predates rotation. `--retire-previous` is refused
until every member serves certificates from the new CA. Like `cloop hub key`, it
writes the state database directly and tells every member on the cluster bus.

#### `cloop hub key escrow`

Every key-encryption key derives from `CLOOP_SECRET_KEY` — unless a KMS holds it
— so rotation cannot help if that value is lost. An escrow file holds it sealed
under a passphrase you choose (argon2id, 64 MiB, then AES-256-GCM); the hub
records only the escrow's id and the key's fingerprint. Keys held by a KMS are
neither opened nor recovered by an escrow: `export` and `verify` list them as
`KMS-HELD`, and only access to that KMS key recovers them.

```bash
cloop hub key escrow export --output /secure/cloop-hub.escrow   # seal the key in this environment
cloop hub key escrow verify /secure/cloop-hub.escrow            # rehearse: does it open, and open this hub?
cloop hub key escrow verify /secure/cloop-hub.escrow --record   # record it again after an older restore
cloop hub key escrow import /secure/cloop-hub.escrow            # recover it into the hub's key file
cloop hub key escrow import /secure/cloop-hub.escrow --stdout   # print CLOOP_SECRET_KEY=… instead
```

| Flag | Applies to | Default | Description |
|------|-----------|---------|-------------|
| `--output` | `export` | — | Where to write the escrow file (required). A path inside a `.cloop/` directory is refused |
| `--force` | `export` | `false` | Replace an existing escrow file at `--output` |
| `--force` | `import` | `false` | Replace a different key already in the key or env file; the old file is kept as `<file>.pre-import.<UTC>` |
| `--passphrase-file` | all | the terminal | Read the passphrase from a file, or `-` for stdin. One trailing newline is stripped |
| `--record` | `verify` | `false` | Record this escrow as the hub's, once it is proven to open the hub's sealing keys |
| `--key-file` | `import` | `CLOOP_SECRET_KEY_FILE`, else `cloop-secret-key` in the hub's directory | The key file to put the key into, mode 0600 — not inside `.cloop/` |
| `--env-file` | `import` | `.cloop/hub.env`, when the hub keeps its key there | The env file to put the key into instead; every other line is kept |
| `--stdout` | `import` | `false` | Print the assignment instead of writing a file |
| `--workdir` | all | current directory | Hub directory holding `.cloop/state.db` |

`export` escrows the current key and refuses one that — with
`CLOOP_SECRET_KEY_PREVIOUS` beside it, mid-way through a change of root — does
not open the hub's sealing keys, or a passphrase under 15 characters, and reads
the file back and opens it before it reports success. `verify` exits 1 when the file does not open or does not open
the hub. `cloop hub doctor` reports `secret_key.escrow`: a warning while no
escrow is recorded, a failure when the one on record holds another key than the
one in use. See the [runbook](../operations/runbook.md#escrowing-the-sealing-key).

### `cloop db backup` and `cloop db restore`

Hot backups of `.cloop/state.db`, and a restore that checks a backup before it
swaps anything.

```bash
cloop db backup                                              # .cloop/backups/state-<UTC>.db
cloop db backup --output /var/backups/cloop/state-<UTC>.db
cloop db restore <backup> --check                            # the preflight alone; writes nothing
cloop db restore <backup> --force --reason "disk failure"    # restore over a live database
```

The backup's sidecar (`<backup>.meta.json`) records the SHA-256, the sealing
keys the backup's secrets depend on and where its audit chain ends, all sealed
under a key derived from `CLOOP_SECRET_KEY`. A restore refuses — changing
nothing — a backup that fails its integrity check, does not match its sidecar,
carries a seal that does not verify, or holds secrets the `CLOOP_SECRET_KEY` it
runs with cannot open, and any restore while a hub still serves the database;
then it records itself as an `audit.restored` row and a sealed restore record
the audit checkpoints accept. A backup whose keys a KMS holds
([`secrets.kms`](configuration.md#sealing-keys-in-a-kms-secrets)) restores only
where that KMS answers: the preflight asks it, says so in its report either way,
and refuses — naming the KMS — without it.

| Flag | Default | Description |
|------|---------|-------------|
| `--reason` | — | Why (required); recorded with the restore |
| `--check` | `false` | Run the preflight only |
| `--force` | `false` | Overwrite a live database; the old file is kept as `.pre-restore.<UTC>` |
| `--skip-checksum` | `false` | Do not check the sidecar at all — for a backup whose sidecar was lost |
| `--allow-unsealed` | `false` | Accept a sidecar whose seal cannot be checked here; the digest is still checked |
| `--accept-secret-loss` | `false` | Restore although the key cannot open the backup's sealing keys; retires them, losing what they seal (recorded). Needs a `CLOOP_SECRET_KEY` |
| `--checkpoints` | `audit.checkpoints.file` | Where to look for superseded checkpoints and append the restore record |
| `--port` | `8080` | The hub whose per-instance overlay to merge over `config.yaml` when reading `secrets.kms` |

Exit codes: 0 restored and recorded, 1 refused or failed, 2 could not run, 3
restored but not fully recorded. The procedure and a drill to rehearse it are in
the [runbook](../operations/runbook.md#backup-and-restore).

### `cloop hub token static`

The deprecated static `--token` / `CLOOP_UI_TOKEN`: whether running hubs still
accept it, its last use, and retiring it on every member without a restart.

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
| `--reason` | `retire` | — | Required; recorded with the retirement and in the audit trail |
| `--fingerprint` | `retire` | — | The token to retire, by at least 8 characters of the fingerprint `status` prints, when hubs hold several |
| `--force` | `retire` | `false` | Retire it although a hub with no single sign-on and no active admin API token would be left with nobody able to administer it |

The token is found without its value: every hub process holding one reports its
fingerprint and last use to the control plane, and `CLOOP_UI_TOKEN` exported in
this shell names one too. `retire` posts a notice on the hub bus; members refuse
the token within about a second and close the dashboard streams and sandbox
terminals it opened, and a member started with `ui.cluster.exclusive` refuses it
within 30 seconds. Retirement is per value: deploying a new `CLOOP_UI_TOKEN`
issues a new token, and the retired one is refused for good. See
[Retiring the static token](../security/model.md#retiring-the-static-token).

### `cloop hub session`

List and terminate signed-in dashboard sessions. Operates on the session table
directly, so it keeps working when the HTTP listener does not — which is the
situation that tends to produce the need for it.

```bash
cloop hub session list                                     # who is signed in
cloop hub session list --identity alice@example.com        # ...for one person
cloop hub session list --json                              # for scripting
cloop hub session revoke 3f9c1e7a --reason "stolen cookie, INC-4412"
cloop hub session revoke --identity alice@example.com --reason "compromise INC-4412"
cloop hub session revoke --all --reason "rotating IdP client secret"
```

`list` shows each session's kind — `browser`, or `cli` for a terminal signed in
with [`cloop login`](#cloop-login) — and `--json` adds the host name a
terminal reported as `client`. A terminal session is revoked exactly as a
browser's is, and closes what it holds open the same way.

`revoke` requires exactly one selector — an id, `--identity`, or `--all` — with
no default, because the three differ by two orders of magnitude in blast radius.
A revocation is announced to running hubs, which stop honouring the session and
close the dashboard streams and sandbox terminals it opened within about a
second. A hub started with `ui.cluster.exclusive` reads no announcements: it may
serve a revoked session from its cache for up to 30 seconds, and closes what it
opened at the next 30-second re-check after that. `cloop hub token revoke` and
`cloop hub user offboard` announce what they revoke the same way.

### `cloop hub user offboard`

Everything one identity can still do on the hub, ended in one operation, and
everything they keep here destroyed. Resolves an email or an IdP subject to
every identifier of the same person first; `--dry-run` prints exactly the set
the write acts on.

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

Severed in one transaction: sessions, API tokens, glasses links, project
memberships, and a deny binding. Then, in order, each reporting its own failure:
secret leases on their projects, the grants over their personal secrets
(revoked), the secrets themselves (deleted through the broker, sealed bytes
overwritten), pending grant requests (withdrawn), their running tasks (stopped),
and their Claude Code login on every hub member (cancelled, logged out,
removed). Projects they own are reported, never deleted. Needs no
`CLOOP_SECRET_KEY`. A partial run exits non-zero. See the
[runbook](../operations/runbook.md#somebody-leaves).

### `cloop hub user hold`

Standing legal holds. Every offboarding of a held identity — this command's,
the dashboard's, or one the identity provider triggers over SCIM — keeps the
person's personal secrets and Claude Code homes, as `--keep-credentials` does,
and records `user.offboard_hold`.

```bash
cloop hub user hold place alice@example.com --reason "litigation LH-17"
cloop hub user hold list
cloop hub user hold release alice@example.com --reason "LH-17 closed"
```

An identity is an email or `sub:<subject>`. `--reason` is required to place or
release a hold (at least four characters to place one — it is what the next
administrator reads). Releasing destroys nothing: run the offboarding again to
finish what the hold kept. `--json` prints the list for scripting.

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
| `credential rotate <name\|id>` | New secret, same name and id. `--grace` keeps the replaced secret working for that long, at most `168h`; without it the old one stops now |
| `credential revoke <name\|id>` | Both secrets end at once. `--reason` is required |
| `credential list` | Every credential, live and revoked, with when each was last used |
| `status` | The credentials, the match claim, and the provisioned directory: users active and suspended, groups, and the users no hub identity matches or several do |

Each takes `--workdir` and `--json`. The same operations are under
**Settings → Provisioning (SCIM)** and `/api/scim`, gated on `user.manage`.

### `cloop hub quota`

Per-identity quota overrides: the one-off cap applied to a single tenant. Most
quota policy belongs in `ui.quotas` in `.cloop/config.yaml`; this edits the
exception.

```bash
cloop hub quota list                                       # overrides and usage
cloop hub quota set alice@example.com \
  --limit daily_cost_usd=5 --limit max_concurrent_tasks=2 \
  --reason "runaway plan INC-4413"
cloop hub quota set alice@example.com --unset max_projects --reason "back to policy"
cloop hub quota clear alice@example.com --reason "INC-4413 closed"
```

Resources are named rather than flagged, so a resource added later needs no CLI
change: `max_projects`, `max_concurrent_tasks`, `max_concurrent_reproductions`,
`max_executors`, `max_sessions`, `daily_token_budget`, `daily_cost_usd`.

`set` and `clear` **refuse while a hub holds the control-plane lease** and point
at `PUT /api/quotas/{identity}`. The enforcer loads overrides once at startup, so
a write behind a live hub would neither take effect nor survive the next edit
made from the Quotas panel.

### `cloop hub limits`

Per-project resource ceilings: how much CPU, memory, disk and how many processes
one project's sandboxes may be given. The fleet-wide ceiling lives in
`executors.limits` in `.cloop/config.yaml`; this holds a single project below it.

```bash
cloop hub limits list                                      # both ceilings, and every capped project
cloop hub limits set /srv/projects/noisy \
  --memory 2g --cpu 2 --reason "OOMing the build box"
cloop hub limits set /srv/projects/noisy --memory 0 --reason "memory cap lifted"
cloop hub limits clear /srv/projects/noisy --reason "moved to its own node"
```

`set` merges onto the stored ceiling, so capping memory leaves an existing CPU
cap alone; pass a resource explicitly as `0` to uncap just that one. Sizes take
the same grammar as the rest of the executor config (`512m`, `2g`, or a bare
integer read as megabytes).

The two ceilings compose by getting tighter and neither can be raised by the
project — a project's own `.cloop/sandbox.yaml` is a request, and a ceiling
bounds it even when it asks for nothing, because an omitted key means *no limit*
rather than "the default".

Unlike `hub quota`, these **do not refuse while a hub is running**. Ceilings are
read from the database on every dispatch rather than cached at startup, so an
edit binds the next task to start.

### `cloop hub role`

Runtime role bindings that layer over `ui.oidc`. This is the emergency demotion
path: `oidc.admin_emails` and `oidc.role_mappings` are read at startup, so
without it, demoting a compromised administrator means editing config and
redeploying.

```bash
cloop hub role list                                        # runtime and configured
cloop hub role list --identity alice@example.com
cloop hub role grant email bob@example.com --role maintainer --project payments --reason "INC-4414"
cloop hub role revoke email alice@example.com --reason "credential compromise INC-4412"
cloop hub role revoke email contractor@example.com --project payments --reason "scope reduction"
cloop hub role delete rb_e1be642bd28f --reason "investigation closed"
```

`revoke` *writes* a deny binding rather than deleting a grant, which is what
lets it work against authority this table never issued. `delete` removes a
binding row and is the only way back from a deny.

Precedence between the two layers is fixed: **deny wins, and the database
overrides config**. A deny beats every other binding at every specificity,
including the global admin binding `oidc.admin_emails` produces. Bindings are
read on a 10-second TTL, so these take effect on a running hub without a restart
and take no lease.

| Flag | Applies to | Description |
|------|-----------|-------------|
| `--reason` | every mutation | Required. Recorded in the audit trail with the operating OS user |
| `--workdir` | all | Hub directory holding `.cloop/state.db` |
| `--identity` | `session list/revoke`, `role list` | Email address or IdP subject |
| `--project` / `--executor` | `role grant/revoke` | Narrow the binding instead of applying it everywhere |
| `--json` | every `list` | Machine-readable output |

The three incident playbooks these compose into — stolen session, runaway
tenant, compromised admin — are in the
[runbook](../operations/runbook.md#access-emergencies).

### `cloop project members`

Who besides its owner may reach a project on a hub with single sign-on — the
CLI side of the Members card on a project's Overview. It writes the hub's
control-plane database directly, like `cloop hub role`, so it works while the
listener does not, and it checks no role: whoever can run it can already write
that database.

```bash
cloop project members list                                   # every membership on the hub
cloop project members list payments --json
cloop project members add payments bob@example.com --role operator --reason "pairing on the ledger"
cloop project members add payments bob@example.com --role viewer --reason "read-only from now on"
cloop project members remove payments bob@example.com --reason "moved teams"
```

`<project>` is a registered project's name or its directory; a feature is shared
with its project and is refused. `<identity>` is an email or `sub:<subject>`.
`add` on an existing member changes their role. A membership only adds access —
see [Project members](../security/model.md#project-members) for what a role means
with and without role mappings. Each change commits with its audit row and is
announced on the hub cluster's bus, so running hub processes apply it at once
and close a removed member's open dashboards; they re-read the table every few
seconds regardless.

| Flag | Applies to | Description |
|------|-----------|-------------|
| `--role` | `add` | `viewer` (default), `operator`, `maintainer` or `admin` |
| `--reason` | `add`, `remove` | Required. Stored with the membership and recorded in the audit trail |
| `--workdir` | all | Hub directory holding `.cloop/state.db` |
| `--json` | `list` | Machine-readable output |

### `cloop hub telemetry`

Read the diagnostic trail the dashboard and the display-glasses page record —
the gestures they received, the views they opened, the requests they issued and
any errors. It exists because those front ends run where the hub cannot look:
the glasses have no console, no network inspector, and a wearer whose entire
reporting channel is a sentence of prose.

```bash
cloop hub telemetry sessions                    # recent page loads, newest first
cloop hub telemetry sessions --source glasses   # just the wearable
cloop hub telemetry show <session>              # one trail, forwards, in order
cloop hub telemetry show <session> -v           # with urls, stacks and detail
cloop hub telemetry list --kind error           # recent errors across all sessions
cloop hub telemetry list --grep /api/tasks      # anything touching an endpoint
cloop hub telemetry prune --before 7d           # delete old events now
```

Start with `sessions`: an investigation arrives as "somebody reported a problem
around ten past four" and has to become a session id first.

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

Run it from the hub's own directory, or point `--workdir` at it. The command
refuses to create a database it cannot find rather than reporting an empty one:
"no telemetry recorded" from the wrong directory reads as "the instrument is
broken", which is the one wrong answer a diagnostic tool must not give.

Collection is **off unless an operator turned it on** — switch it on in
Settings → Telemetry in the dashboard, or with `ui.telemetry.enabled: true` —
so an empty trail on a hub nobody configured is the expected answer rather than
a fault. While on, credentials are scrubbed before storage and the table trims
itself at 50,000 rows. The Telemetry tab shows the same data, gated on
`audit.read`. See [front-end telemetry](../operations/telemetry.md).

### `cloop hub audit forward`

Where the audit trail goes as it is written, and whether it gets there. The
forwarding itself is the cluster leader's duty inside `cloop ui`; these read
what it leaves in the control plane, so they answer with the hub up or down.

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
| `--hub` | `prune` | Hub directory whose forwarding cursors bound the prune (default: this database, and the hub it names) |
| `--force` | `prune` | Prune rows a sink has not acknowledged; it never receives them |

`status` exits 1 when a sink is refused at load, has never delivered (a sink no
hub has started yet included), or lags beyond `audit.forward.max_lag`. `verify`
reads a JSON sink's file, a collector's export, HEC events or syslog lines, and
exits 2 on a gap, a fork (one id with two hashes), a bad hash, a broken link,
or a file holding no forwarded record (a CEF stream cannot be verified); a
repeated row is counted, not reported. `cloop db maintain` takes `--audit-hub` and
`--force-audit-prune` for the same hold. See
[forwarding the trail off the box](../operations/runbook.md#forwarding-the-trail-off-the-box).

---

## Network egress

`cloop egress grant / list / test / revoke` issue and inspect the leases that
let an isolated sandbox reach the outside world through the control plane's
proxy — see [the secrets guide](../guides/secrets.md#egress-leases). The
subcommand below is about the other enforcement point.

### `cloop egress firewall`

Render the packet filter an egress authorisation compiles to, or ask what it
would do to one address.

The two enforcement points answer different questions and an operator has to be
able to see both. `cloop egress test` asks the *proxy* "may I connect to this
URL", which is the layer-7 answer and depends on the workload choosing to use
the proxy. This asks the *packet filter* "would this packet leave", which is the
answer that binds a workload that does not.

The rendered output is the same text the driver installs, so it can be diffed
against `nft list table inet cloop_sbx_<id>` on a host or
`kubectl get netpol -o yaml` in a cluster. Nothing here touches the host: it
compiles and prints.

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
| `--drop-denied` | | Render every deny as a silent drop instead of a refusal |

`--format nft` renders the in-namespace form (output, input and forward chains,
all defaulting to drop); `nft-bridge` renders the host-side form that filters
one bridge. `--check` accepts an optional `/tcp` or `/udp` suffix and defaults
to TCP.

**Previewing a configuration before writing it.** The rules are printed in
evaluation order, first match wins, with the reason that will appear in the
ruleset and in the audit trail:

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

The granted `10.8.0.0/24` is allowed *before* `10.0.0.0/8` is dropped: that
ordering is the waiver rule, and it is why the grant buys that prefix on that
port and nothing else. Two kinds of drop sit *ahead* of the granted allow, so a
granted range never opens them: the IPv6 encodings that carry an IPv4 address (a
packet filter cannot unwrap one, so it drops the prefix whole), and each cloud
metadata service the range contains — `169.254.0.0/16` would hold six of them —
which only the service's own `/32` or `/128` in `--cidrs` opens.

**Seeing what a hostname allowlist became.** The warning is the point of the
command, not decoration — it appears in every format, including the nft
comments:

```console
$ cloop egress firewall --internet --ports 443 --format rules
IP-layer egress filter  mode filtered, 23 rules, from flags

warning: every public address is reachable on port 443; only the private, loopback, link-local, CGNAT and metadata ranges are filtered

warning: no resolver is allowed, so DNS will fail: name lookups leave the sandbox on UDP/53 and this policy drops them. Pass the sandbox's resolvers, or use the broker, which resolves on its behalf.
```

With `--grant <id>`, a grant whose allowlist is hostnames produces a warning
naming those hostnames and the port they widened to, because that is the single
most useful thing this command reports.

**Asking about one address — `--check`.** The verdict is on stdout and *also*
in the exit status: **0** when the packet would leave, **1** when it would be
denied. An operator automating "is this sandbox still confined" should not
have to parse prose.

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

The third is the useful one: the address is inside the granted range, and it is
dropped anyway, because the waiver covers the prefix *on its ports*. The reason
names the rule that decided, so "why can my sandbox not reach this" has an
answer rather than a guess.

**Rendering what a host would run.** `nft-bridge` is the form the container
driver installs, and both hooks carry the same rules — `forward` for
destinations the host routes onward, `input` for destinations that belong to
the host itself:

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

Every deny path jumps to the `deny` chain, which refuses: a TCP reset, or an
ICMP "administratively prohibited", so a blocked connect fails at once rather
than after a timeout (`--drop-denied` renders a plain drop instead). The chain
policy is `accept` and the deny is explicit, because base chains on the same
hook all run: a `policy drop` here would take down every other container on the
host. The driver installs the same ruleset with a rate-limited `log … group N`
statement ahead of each deny path, which is how a run's refusals reach its
history; this preview has no group to log to, so it shows none. Each chain returns immediately for traffic that is not
from this sandbox's bridge. The `add table` / `delete table` / `table` preamble
makes a re-apply replace rather than accumulate — `add` is a no-op on an
existing table, which is what makes the `delete` safe on a first run — and
`nft -f` commits the whole thing as one transaction. Every rule carries a
`counter`, which is what makes
`nft list table inet …` useful when a sandbox cannot reach something — see the
[runbook](../operations/runbook.md#incident-playbooks).

Full context: [IP-layer egress filtering](configuration.md#ip-layer-egress-filtering)
for the config keys, and [the security model](../security/model.md#the-network-the-sandbox-sits-on)
for what each layer does and does not bind.

---

## Cleaning up after a killed control plane

A hub that dies mid-run does not take its workloads with it. Containers, Pods
and edge-device processes keep running, and since Task 20191 the next hub
reattaches to the ones it can still identify and sweeps the rest — so these two
commands are for the residue nothing is left to sweep: a host whose hub is not
running, a runtime shared with one that never will be, and the half of the
worktree cleanup that is too destructive to do unattended. See
[the restart sweep](../architecture/executors.md#the-restart-sweep) for what the
hub does on its own.

### `cloop executor reap <executor-id>`

Remove sandbox containers or Pods this control plane created but no longer
tracks. It takes exactly one executor ID and applies to `container` and
`kubernetes` executors; anything else is refused by kind.

Both backends remove **terminated** workloads immediately, and **running** ones
once they are older than that executor's
[`orphan_grace_period_seconds`](configuration.md#container-sandbox) — ten minutes
by default. The running case is the one that matters: an exited container holds a
name and a writable layer, while a running orphan keeps burning a core, or a
node's CPU and a ResourceQuota slot, with nobody reading its output.

The grace period is what makes touching a running workload safe. A container or
Pod that appeared moments ago may belong to a control plane that is starting
right now, or to this one between dispatching a workload and recording its
handle; anything older than the grace period has outlived both windows. A
running container is additionally required to carry this executor's own labels,
so two container executors sharing a host cannot reap each other's work.

### `cloop worktree list` / `cloop worktree prune`

Parallel task execution gives each task its own git worktree under
`.cloop/worktrees/task-<id>`, on a branch named `cloop/task-<id>-<slug>`. Both
are removed when the task finishes; a run killed in between leaks both. Both
commands act on the current working directory's repository.

```console
$ cloop worktree list
TASK     BRANCH                                 DIR        GIT        AGE
17       cloop/task-17-add-retry                yes        yes        3h0m0s
23       cloop/task-23-fix-parser               yes        no         26h0m0s
```

`DIR` is whether the directory is on disk, `GIT` whether `git worktree list`
still registers it. The two disagreeing is not an inconsistency to ignore, it is
the leak: a directory with no registration is what a `git worktree prune` leaves
behind, a registration with no directory is what an `rm -rf` leaves, and a sweep
that consults only one source is blind to one of them. `list` also prints the
`cloop/task-*` branches present in the repository, which is the population
`prune` will not touch unless asked.

`prune` removes the directories. Start with `--dry-run`.

| Flag | Default | Description |
|------|---------|-------------|
| `--dry-run` | `false` | Report the whole plan, including branches, without changing anything |
| `--min-age` | `2h0m0s` | Only prune worktrees idle for at least this long; `0` disables the guard |
| `--delete-branches` | `false` | Also delete `cloop/task-*` branches already merged into the base |
| `--base` | the checked-out branch | Branch to test merged-ness against |

**`--min-age` is the only flag here that can destroy work.** A live parallel
run's worktrees are in that directory *right now*, and an agent that has been
thinking for twenty minutes has written nothing in that time — mtime cannot tell
"finished an hour ago" from "still running and quiet for an hour". Two hours is
long enough to cover any plausible quiet period inside a running task; passing
`--min-age 0` is how you say you have established that nothing is running, and
git cannot restore what was never committed. A `git worktree lock` is honoured
whatever the age, and a directory whose age cannot be read is kept.

**`--delete-branches` cannot delete unmerged work at any setting.** A branch is
deleted only if its commits are already contained in `--base`, and the check is
enforced twice — an explicit `git for-each-ref --merged` query, and then `git
branch -d`, which refuses an unmerged branch on its own authority. `-D` is never
used. Squash-merged branches are therefore kept and reported, because no ancestry
test can see a squash: a stale ref costs a line of output, and being wrong the
other way costs a task's only copy of its work.

Every entry the sweep spares is reported with its reason, because the question
after a prune is usually "why is this directory still full". A non-zero exit
means some worktree could not be removed — a permission error, a busy mount —
and names it; the others were still collected.

---

## Device forwarders

A device forwarder carries one on-prem USB device or network segment to the hub
over an outbound tunnel; a binding gives it to one project's runs. See
[the guide](../guides/device-forwarders.md) for the whole flow. Every command but
the first acts on the control plane in the current directory.

### `cloop forward`

Run the forwarder on the on-prem machine: `cloop forward --bundle <bundle>` the
first time, plain `cloop forward` after (the credential is saved `0600` at
`~/.cloop/forwarder.json`). `--usb vendor:product[:serial]` or `--interface
<name>` names the device when no bundle does.

### `cloop forward enroll` / `list` / `revoke <id>`

`enroll --name N (--usb V:P[:S] | --interface I)` mints a single-use token and
prints the `cloop forward --bundle …` command; `list` shows the forwarders;
`revoke` revokes a token or a forwarder, its bindings with it, and tells the
running hubs, which cut its live session and detach its device from every run.

### `cloop forward bind <forwarder-id>` / `bindings` / `unbind <binding-id>`

`bind --project DIR [--virtual-executor ID] [--ttl 24h] [--target NAME
--address CIDR --gateway IP --mtu N] [--note TEXT]` makes the forwarder's device
available to the project's runs (only on that virtual executor, when given) for
the TTL — at most 90 days. `bindings [--project DIR] [--all]` lists them;
`unbind [--reason TEXT]` revokes one and tells the running hubs, which detach the
device from a run holding it. Each is audited (`forwarder.bind`,
`forwarder.unbind`).

## Executor internals

Commands an executor runs on your behalf. They are documented because you will
meet them in a container log or a failing init container, not because you are
expected to type them.

### `cloop workspace provision`

Materialise a git workspace into a directory, then exit. This is what an
isolated executor runs *before* the harness starts: a Kubernetes init container
named `workspace`, or any other place that has to hold the code before the
workload does. The Kubernetes driver builds the argv, so the flags below are a
wire format between the driver and this command rather than a UI.

> Unrelated to the other `cloop workspace` subcommands (`add`, `list`,
> `switch`, …), which manage multiple cloop projects from one root. Same noun,
> different feature.

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

**The project comes with the tree** (Task 20402). A clone of a source
repository is not a cloop project, so for a seeded run the Kubernetes driver
projects the hub's project state into this container — and this container only —
and passes `--seed`. After the fetch the command writes it into the checkout,
exactly as a remote agent does after its own, and keeps `.cloop/` out of the
tree's commits (an `info/exclude` entry, and skip-worktree on anything the
repository tracks under it), so neither the harness nor the push write-back can
commit the hub's project into the repository. A `.cloop/` the repository commits
is superseded: its database is removed from the working tree first, and the run
sees the hub's project. `--seed-copy` leaves the bytes where the harness's
wrapper reads the run's changes back against them. See
[Kubernetes: the seed in a Secret, the outcome in the log](../architecture/executors.md#kubernetes-the-seed-in-a-secret-the-outcome-in-the-log-task-20402).

`--dir` must be absolute: a relative path would resolve against whatever working
directory the process happens to have, which inside a Pod is the image author's
choice rather than the driver's. The repo URL must be `https://` and must not
embed credentials — see [the workspace contract](../architecture/executors.md#workspace-provisioning)
for why.

**Credentials come from the environment**, because that is the only channel a
Pod has that is neither an argv (`/proc` publishes those to every process under
the same uid) nor a file (which outlives the process that needed it):

| Variable | Meaning |
|----------|---------|
| `CLOOP_WORKSPACE_TOKEN` | the bare token; absent or empty means an unauthenticated fetch, which works for a public repository |
| `CLOOP_WORKSPACE_USER` | the basic-auth username; defaults to `x-access-token`, which is what GitHub expects alongside a PAT |

Both are read and **removed from the process's environment before anything is
spawned**, and no output of this command can contain either — every byte it
writes and every error it returns is passed through the same redaction the
provisioner applies.

The sequence is `git init`, `remote add origin`, `fetch`, then
`checkout --detach FETCH_HEAD` — not `git clone`, because `clone` cannot name a
bare commit SHA. A directory that already holds a checkout of the *same* remote
is fetched into rather than re-cloned; one holding a *different* remote is a
refusal naming both URLs, since re-cloning would discard whatever is there.

Running it by hand is the way to reproduce a workspace failure outside a
cluster:

```bash
CLOOP_WORKSPACE_TOKEN=ghp_… cloop workspace provision \
    --dir /tmp/repro --repo https://github.com/acme/app.git --ref main
```

A non-zero exit means the tree is not there. The message names the machine, the
repository and the directory, and is safe to paste into a bug report.

### `cloop workspace writeback`

Run a harness, then return what it produced from a sandbox that will not
outlive it: the files it changed, as a commit on a `cloop/` branch, and — for a
seeded run — the project state it recorded. It is the harness container's
command on Kubernetes and in a container executor's feature mode, with the
harness's own argv after `--`; it forwards the harness's output and signals and
exits with its status. Like `provision`, its flags are a wire format the driver
renders.

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

A delivery (`--push` or `--bundle`) is required unless the command is returning
only a seeded run's project state; then `--repo`, `--branch`, `--base`,
`--message` and `--max-bundle-bytes` are refused rather than ignored. The
write-back's report is one `##cloop-writeback-v1##` line on stdout, printed
whatever happened. The project-result frame follows it — a Pod's log is its only
way home — and the driver lifts it out of the log before the live log and the
run's artifact see it, so it only shows in `kubectl logs`.

