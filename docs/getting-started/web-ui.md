# The web dashboard

Everything cloop does from a terminal it also does from a browser: creating a
project, editing its goal, adding and reordering tasks, toggling run options,
starting and stopping a run, and watching the output arrive live. This page is
about the single-user case — one person, one machine. Running it for a team is
a different setup, and the last section says where that is documented.

- [Starting it](#starting-it)
- [What it authenticates by default](#what-it-authenticates-by-default)
- [The layout](#the-layout)
- [Projects](#projects)
- [A project's Overview](#a-projects-overview)
- [Tasks](#tasks)
- [Run options](#run-options)
- [Settings](#settings)
- [Live updates](#live-updates)
- [Beyond one user on one machine](#beyond-one-user-on-one-machine)

---

## Starting it

```bash
cloop ui                                    # port 8080, opens your browser
cloop ui --port 9090 --no-browser
cloop ui --scan ~/Projects                  # find every cloop project under a directory
cloop ui --projects /srv/app --projects /srv/api
```

| Flag | Default | Meaning |
| --- | --- | --- |
| `--port` | `8080` | Port to listen on |
| `--no-browser` | `false` | Do not open a browser window at startup |
| `--projects` | — | Additional project directories, repeatable |
| `--scan` | — | Scan a directory for cloop projects and add them |
| `--token` | — | **Deprecated** static bearer token; also read from `CLOOP_UI_TOKEN` |
| `--rate-limit` | `20` | Requests per second per IP (`0` uses the default) |
| `--rate-burst` | `50` | Burst size per IP (`0` uses the default) |
| `--tls-cert` / `--tls-key` | — | Serve HTTPS directly; overrides `ui.tls` in the config |

Projects found by `--projects` and `--scan` are written into the per-user
registry at `~/.cloop/projects.json`, so they are still listed next time
without the flags. `CLOOP_HOME` relocates that registry — useful when two hubs
share a Unix account. TLS, WebSocket connection caps and the origin allowlists
come from `ui.*` in `.cloop/config.yaml`; a YAML parse error here is fatal
rather than a warning, because it is where the security settings live. See
[the configuration reference](../reference/configuration.md#tls).

**There is no bind-address flag.** The listener is opened on `:<port>`, which
means every interface on the machine, not just loopback. The startup line
prints a `localhost` URL because that is the address to open in a browser — not
because the socket is restricted to it.

---

## What it authenticates by default

**Nothing.** With no `--token`, no scoped API token and no OIDC configured,
every route — including the ones that start a run, edit a plan or delete a
project — is served without authentication. Combined with the bind behaviour
above, a plain `cloop ui` on a machine other people can reach is a machine
other people can run code on.

That default is the right one for a laptop and wrong for anything else. If the
port is reachable from a network, configure one of the real options before you
start it:

- **Scoped API tokens** (`cloop hub token create`) for scripts and CI. They
  carry roles, can be limited to specific projects, expire, and are revocable
  one at a time.
- **OIDC single sign-on** (`ui.oidc.*`) for people, with claim-based RBAC.

`--token` / `CLOOP_UI_TOKEN` still works and prints a deprecation warning at
startup: it bypasses RBAC entirely, sees every project on the hub, and cannot
be revoked for one caller without breaking every other. Both proper options are
covered in [the security model](../security/model.md).

---

## The layout

The tab bar is split into two labelled groups. **Project** tabs show one
project at a time — Overview, Tasks, Activity, Kanban, Timeline, Knowledge
Base, Dependencies, Risk Matrix, Analytics, Chat, Assistant, Replay and
Provider Calls. **Global** tabs apply across the whole hub: Projects, Budget,
Executors, Secrets, Audit, Quotas and Settings. The last three are hidden
outright unless your role carries the matching permission, so a single-user
install typically sees Projects, Budget, Executors and Settings.

The screenshots below were taken from an earlier release; the tab bar has grown
since, but the panels they show work the same way.

---

## Projects

![The Projects tab: fleet-wide counters across the top, then one row per registered project with its goal, run status, progress bar, task count, last activity and provider, plus Run / PM / Stop buttons.](../screenshots/01-projects-overview.png)

The Projects tab is the fleet view: counters for projects, active runs, total /
done / failed tasks and total steps, then one row per project. Each row carries
its goal, a live status pill, a progress bar, `done/total` tasks, when it last
did anything, and the provider and model it is using. Clicking a row opens it in
the Project tabs.

**Adding one.** **+ New Project** opens a modal asking for a directory and a
goal, with optional Provider, Model and Effort pickers, a **PM mode** checkbox
and **Start run immediately**. A collapsed **Access (optional)** section can
pick the executor the project runs on and attach credential grants at the same
time; if the executor or any grant is refused, the whole creation is rolled back
rather than left half-provisioned. In a directory that is not yet a cloop
project, the Overview tab shows an *Initialize a project* panel that does the
same job for the working directory.

**Running one.** Each row has **Run** and **PM** buttons, and **Stop** while a
run is in flight — so you can drive several projects without leaving the list.

**Hiding and deleting.** **Hide** removes a project from *your* dashboard only;
it keeps running, other users still see it, and it comes back from
**Settings → Hidden Projects**. **Delete** is separate and asks for
confirmation, with an opt-in checkbox to also delete the project directory from
disk.

---

## A project's Overview

The Overview tab is the control panel for one project, top to bottom:

| Card | Contents |
| --- | --- |
| **Project Goal** | the goal, the status badge, and an **Edit** button |
| **Instructions / Constraints** | the extra instructions the AI is given, also editable |
| **Overview** | Steps, Provider, Executor, Mode, Tokens, Est. Cost, Created, Updated |
| **Active Options** | the persistent run flags — see [Run options](#run-options) |
| **Claude Code Subscription Caps** | weekly / 5-hour / Opus / Sonnet utilisation ceilings, shown only on the `claudecode` provider |
| **Controls** | **Run**, **Pause / Stop** while running, **Refresh**, **Voice** |
| **Live Output** | the running step's output as it arrives, with **Clear** |
| **Event History** | steps merged with task starts, completions, failures, skips, heals, evolve cycles and status changes |

Two of the stat cards are also buttons. **Provider** opens a Provider & Model
picker whose choice is saved on the project and used by every subsequent run
until changed; the Effort selector there applies to `claudecode` only and says
so. **Executor** picks where this project's harness actually runs, and takes
effect on the next run — work already in flight stays where it started.

---

## Tasks

![The Tasks tab: a search and filter bar, an inline Add Task form with title, description, priority and dependency fields, then the task list — each entry showing its status, role tags, priority badge and ID, with Done, Skip, Fail, Reset, Edit and Remove buttons.](../screenshots/03-tasks.png)

The list filters by free text, status, priority, assignee and tags, and hides
completed tasks behind a **Show completed** toggle. The header counts what is
done and what is hidden.

**Adding** is the inline form at the top: title, optional description, priority
(`1` = highest) and a comma-separated list of task IDs to depend on. **Add
Task** appends it immediately.

**Editing** happens in a modal with title, description, priority, dependencies
and a per-task **Max minutes** budget (`0` inherits the project default).
The per-row buttons — **Done**, **Skip**, **Fail**, **Reset**, **Edit**,
**Remove** — set status directly; **Remove** asks for confirmation first.

**Reordering** is drag and drop, and the list is the run queue: tasks run top to
bottom, and dragging a row rewrites the priorities the scheduler reads. This
holds while a run is in flight — the orchestrator re-reads the order on every
iteration, so a task dragged to the top is the next one picked up and nothing
needs restarting. Three things bound it:

- **Dependencies win.** A task dragged to the top still waits for whatever it
  depends on. The queue orders what is *ready*; it does not override the graph.
- **Only pending tasks have a position.** Completed and currently-running rows
  carry no drag handle: one is history, the other has already left the queue.
- **Pinned tasks lead.** `cloop task pin` puts a task at the head and keeps it
  there, so a drag across that divider is refused rather than half applied —
  `cloop task unpin <id>` first.

With **max-parallel** above 1 the same order decides which tasks start: the top
*N* of the queue, where *N* is the worker count.

The same plan is visible other ways: **Kanban** as four columns (Pending, In
Progress, Done, Failed/Skipped) with draggable cards, **Timeline** as a Gantt
chart, **Dependencies** as a graph, and **Activity** as a per-task log of every
execution, heal retry and evolve cycle.

---

## Run options

There is no options dialog on the Run button. Every persistent flag is a badge
in the **Active Options** card on Overview, and clicking a badge toggles it:

| Badge | Flag |
| --- | --- |
| Evolve Mode | `--auto-evolve` |
| Innovate Mode | `--innovate` |
| Skip Clarify | `--skip-clarify` |
| Parallel | `--parallel` |
| Plan Only | `--plan-only` |
| Retry Failed | `--retry-failed` |
| Dry Run | `--dry-run` |

Three numeric controls sit in the same card: **Max Parallel** (`-j`, 1–64, the
worker cap when Parallel is on), **Step Timeout** (a duration, or `off`), and
**Task Timeout** (minutes, `0` for none). Task Timeout is applied to
*currently running* tasks within a few seconds, not only to the next one.

Because these are stored on the project rather than passed per click, the
dashboard and the CLI agree: a badge you turn on here is the flag `cloop run`
will use.

---

## Settings

![The global Settings tab: a Configuration section with cards for Default Provider, ClaudeCode, Anthropic and OpenAI — each with its own model, base URL and password-masked API key field, and its own Save button.](../screenshots/05-settings.png)

Settings is global rather than per-project. The **Configuration** section edits
the same provider keys `cloop config set` writes — the default provider, and
per-backend model, base URL and API key for ClaudeCode, Anthropic, OpenAI and
Ollama. Each card saves independently, keys are write-only (blank keeps the
existing value), and a *no key* badge marks a backend that has none. What each
of those keys means is in
[Choosing and configuring a provider](providers.md).

Below it: **Display glasses**, a personal link for Meta Ray-Ban Display glasses
that expires after 30 days and can be revoked; **Hidden Projects**, which says
only how many you have hidden and opens a dialog — one Unhide button per entry
— when you click it, so that landing on this tab for something else does not
put their names on screen; and a **Danger Zone** whose *Reset Project State*
clears step history and resets status while preserving the goal and
configuration.

### On the glasses

The link opens a separate, much smaller page — `/glasses` — that lists your
projects, drills into one project's tasks and shows a single task. Beyond
reading, the only thing it can do is add a task; it cannot start a run, change
an existing task, or reach anything outside the glasses views. Generate the
link with **Read-only** ticked to remove even that.

The glasses have no pointer and no keyboard. Every band or temple gesture
arrives at the page as an arrow key or Enter, so the page provides the cursor
itself:

| Gesture | What it does |
| --- | --- |
| Swipe left / right | Move the selection to the previous / next control. It wraps, so continuing one way always gets you everywhere. If you have scrolled away from the selection, it jumps to what is on screen rather than dragging the page back to it. |
| Swipe up / down | Scroll. On a screen with nothing to scroll they move the selection instead. |
| Pinch | Activate whatever is selected. With nothing selected it takes the cursor back rather than doing nothing. |

The selected control carries a blue ring — that ring is the only cursor there
is, and the page paints it itself rather than leaving it to the browser, so it
keeps working on a runtime with its own ideas about focus. Nothing here scrolls
sideways: the layout is one column, so a sideways gesture is always a selection
move and never a scroll. The page re-reads the hub about once a minute and
patches what changed in place, so a refresh does not move your selection or lose
your place in a long task result.

### Adding a task from the glasses

Inside a project there is a **+ Add task** button above the list. It is always
there when the link may add tasks, and it opens a screen with the ways of
composing one that work on whatever is reading the page:

- **🎤 Speak a new task**, when the device has a microphone — which on Ray-Ban
  Display means the phone, not the glasses (see below).
- **Ready-made tasks**, a short list the hub builds from the project's own
  plan. The first rows name the newest failed or timed-out tasks — *Fix the
  failure in task #63: …* — and the rest are standing jobs worth doing on any
  project: review the recent changes for bugs, add tests for what changed,
  bring the documentation back in line. Each carries a full brief for the agent
  that never has to fit on the display.

Either way the next screen shows what is about to be created, with *Add task*
and *Discard*, so a stray pinch cannot file work. Discarding returns you to the
Add screen rather than the task list, because the next thing you want after
rejecting one is usually another one.

The list exists because the hardware leaves no alternative: with no microphone
and no text input, choosing from a list is the only way to compose anything
with a band that sends arrow keys and Enter. Nothing here calls a model — the
rows are derived from plan state — so opening the screen costs nothing.

---

## Dictating a task

A **Dictate** button sits beside *Add Task* on the Tasks tab. Press it, say the
task, press it again: the recording goes to the hub, comes back as text, and
lands in the title field. It is not submitted for you — speech recognition is
good, not perfect, and the field is right there to correct before you press
*Add Task*.

The button only appears when the hub has a speech backend configured, and the
browser needs an `https` origin (or `localhost`) to reach a microphone at all.

### Dictating a change to a task

The same button sits beside *Description* when you edit a task. It behaves
differently there, because that field already has words in it and "…and make
sure it works on mobile" sounds exactly like "scrap that, this is really about
the migration". So it asks:

| | |
| --- | --- |
| **Replace** | the details become what you said |
| **Add to the end** | the details keep their text and gain a paragraph |
| **Edit with AI** | what you said is an *instruction*, and the model applies it to the details that are there |

The first two are instant and happen in the browser. The third posts the open
draft — not the saved copy, so anything you have typed since opening the modal
is what gets revised — to `POST /api/tasks/{id}/revise`, and costs one provider
call against the project's budget. If the model is unavailable the dialog stays
up, so the other two answers are still one click away.

None of the three saves anything. The text lands in the textarea and *Save
Changes* is still the only way into the plan, which is what makes letting a
model rewrite a task description safe: a misheard instruction is a paragraph you
can read and cancel, never a silent edit. A description that is empty to begin
with skips the question — there is nothing to lose, so the words go straight in.

The glasses page offers the same thing as **🎤 Speak a new task**, on the *+
Add task* screen described above, with a confirmation step — the transcript,
then *Add task* or *Discard* — because a wearer has no keyboard to correct a
wrong word with.

**The glasses cannot record.** Meta's developer guide lists camera, microphone
and `getUserMedia` as unsupported for Ray-Ban Display web apps, so no web app
on that device can hear anything. Dictation therefore runs on the phone the
glasses tether through: open the same saved link there and the control is live.
On the glasses the Add screen says so in one line and offers the ready-made
rows instead, rather than showing a button that cannot work.

### Configuring speech-to-text

The hub transcribes with hosted Whisper on Groq, and only that. `cloop listen`
on your own machine also falls back to a local `openai-whisper` CLI, but the
hub never does: that fallback starts a Python process per request, fed
caller-supplied audio, beside the control plane — which is precisely what
[no host execution](../security/model.md) forbids. So the hub needs a key.

Set it in **Settings → Speech-to-text**, which needs no shell on the hub's
host. The panel reports whether a key is in force and where it came from, and
offers to remove one the hub itself stores. Or from the command line:

```bash
cloop config set stt.groq_api_key gsk_...     # or export GROQ_API_KEY
cloop config set stt.language en              # optional; empty auto-detects
```

The Settings panel writes the key to the **hub's** `.cloop/config.yaml`, never
to the project you happen to have selected, because that is the only config
dictation reads — `/api/dictate` and `/api/transcribe` are called without a
project index. It is therefore its own endpoint, `GET`/`PUT`/`DELETE
/api/config/stt`, rather than a key on `/api/config/set`. The key is never sent
back to the browser; only whether one is set.

| Key | Default | What it does |
| --- | --- | --- |
| `stt.groq_api_key` | `$GROQ_API_KEY` | Credential for hosted Whisper. Required for dictation in the web UI. |
| `stt.model` | `whisper-large-v3-turbo` | Hosted model. |
| `stt.endpoint` | Groq's URL | Point at any OpenAI-compatible transcription server. |
| `stt.language` | auto-detect | ISO-639-1 hint, e.g. `en`, `de`. |
| `stt.provider` | auto | `groq` or `whisper`. Only `cloop listen` honours `whisper`; the hub is hosted-only. |
| `stt.whisper_model` | `base` | Local CLI model, for `cloop listen`. |

A project's own `.cloop/config.yaml` overrides the hub's field by field, so one
key at the hub serves every project while a project that needs a different
language can say so locally. Without a key the button stays hidden and
`GET /api/dictate` explains what is missing.

---

## Live updates

The dashboard holds a WebSocket open at `/api/ws` and falls back to
Server-Sent Events at `/api/events` when a proxy blocks the upgrade. Task
changes, state diffs, run start/stop, step output, provider calls, executor
health and presence all arrive over it — nothing polls, and two people looking
at the same project see the same thing. Concurrent edits to one task are
detected and reported rather than silently overwritten.

---

## Beyond one user on one machine

Everything above assumes the default: one person, one host, work executed as a
child process of the dashboard itself. A shared or hosted deployment needs two
more decisions, and both have their own documentation.

- **Who may do what** — SSO, sessions, roles and scoped API tokens are in
  [the security model](../security/model.md). Start there before exposing the
  port; the defaults on this page are not the ones you want. Turning SSO on
  also splits the Budget tab's Claude Code sign-in, which is otherwise one
  account for the whole hub — see
  [per-user Claude Code logins](../security/claude-code-identity.md).
- **Where the work runs** — the dashboard forking a harness next to itself is
  fine on a laptop and not fine when the code being run was written by a model
  on someone else's behalf. Container, Kubernetes and remote executors, and the
  `executors.allow_host_process: false` switch that makes host execution
  impossible, are in
  [the configuration reference](../reference/configuration.md#execution-backends-executors).

  Each executor card in the **Executors** tab carries three admin dialogs:
  **Sandbox** (host or container, and the engine, runtime and image a container
  gets), **Limits** (the most CPU, memory, disk and processes any one workload
  there may be given), and **Access** (which users and groups may run work on
  it at all). An executor with an empty access list is available to everyone,
  which is how every executor starts. See
  [who may use an executor](../architecture/executors.md#who-may-use-an-executor).
- **Running it day to day** — backup, upgrade, key rotation and incident
  playbooks are in [the operator runbook](../operations/runbook.md).

---

See also: [core concepts](concepts.md), [your first project](first-project.md),
and the [command reference](../reference/commands.md).
