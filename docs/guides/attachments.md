# Task attachments

Files can be attached to a task in two directions:

- **Input files** are files you give the task's agent to work with: a
  specification, a data set, a screenshot of a bug, a log to read. Every
  attempt at the task gets a copy. See
  [Input files for the agent](#input-files-for-the-agent).
- **Results** are files the agent made for a person to look at: a report, a
  chart, a screenshot, a data export or a log. See
  [How a run attaches a file](#how-a-run-attaches-a-file).

Both belong to the task and outlive the runs that used or made them. The
dashboard shows them with the task, previews images and text, and lets you
download any of them.

## Input files for the agent

Attach a file as an input in the dashboard (open the task and press **Add
input files…**, drop files on its Attachments section, or pick them with
**Files** when you add the task) or from the command line:

```bash
cloop task add "Implement the API in the spec" --no-ai --input-file spec.pdf --input-file examples.json
cloop task attachments add 12 screenshot.png --input --note "The broken layout"
```

At the start of every attempt at the task, cloop copies its input files into
the task's **inbox** and tells the agent where it is, in its prompt and in its
environment:

```text
.cloop/attachments/inbox/<task-id>/        # absolute path in $CLOOP_TASK_INPUTS
```

The prompt lists each file with its size, type and note, so the agent knows
what it has before it opens anything. The copies are read-only, made fresh for
each attempt and removed when it ends: an agent that edits one changes nothing
the next attempt sees, and the file you attached stays as it was. Files with
the same name are told apart, as in `rows.csv` and `rows (2).csv`.

A provider that only returns text, such as the Anthropic API, cannot open a
directory. Its prompt gets the contents of the text files among the inputs
instead (Markdown, CSV, JSON, YAML, logs, source code and so on), up to 64 KiB
in all, and the names of the rest.

A file you attach while an attempt is already running reaches the task's next
attempt, not the running one; the dashboard says so when that happens. A file
that cannot be copied, because it is over a limit or its bytes no longer match
what was attached, is named in the prompt with the reason, so the agent can
say that it is missing.

Input files count toward the same [limits](#limits) as every other attachment.
Uploading or attaching one by hand is audited (`task.attachment_add`).

## How a run attaches a file

Every attempt at a task gets an **outbox**, a directory named in the agent's
prompt and environment:

```text
.cloop/attachments/outbox/<task-id>/        # absolute path in $CLOOP_TASK_ATTACHMENTS
```

The agent copies files into it (`cp report.html "$CLOOP_TASK_ATTACHMENTS"/`),
or a script writes its plot there directly. When the attempt ends, cloop moves
every regular file it finds there into the task's attachments and empties the
outbox. Subdirectories become part of the name, so `plots/loss.png` is attached
as `plots/loss.png`. `$CLOOP_TASK_ID` holds the task's id.

The agent doesn't run any command, which matters because the `cloop` on its
`PATH` may not be the build running the task. Only agents that work in the
project with their own tools (Claude Code) are told about the outbox, not
providers that only return text.

What happens to each file when the attempt ends:

| The file is… | Then |
| --- | --- |
| a regular file within the [limits](#limits) | attached, after the credentials leased to the run are scrubbed from its bytes (as they are from the transcript) |
| a symbolic link | not followed and not attached. Copy the file itself. |
| a FIFO, device or socket | not read, not attached |
| nested more than 8 directories deep, or past the 1000th entry | ignored |
| over a limit | not attached |

Everything cloop handled, attached or refused, is removed from the outbox, and
the project's **Event History** gets one `task_attachments` line saying what
was attached, what was not, and why. A file that failed for a reason that may
go away (a full disk, a busy database) stays in the outbox and is tried again.

Attachments are collected when an attempt finishes, fails, times out or is
aborted, so a timed-out benchmark keeps its partial results. If the run was
stopped, paused or died, the files are collected when the run loop exits, or
else when the task's next attempt starts, and are credited to the run that made
them. Deleting a task deletes its outbox, so a new task that gets the same id
never starts with another task's files.

A run attaching its files is not audited, but the journal line names the run
that did it. A person attaching one is audited (`task.attachment_add`), and so
is deleting one (`task.attachment_delete`).

## Attaching by hand

```bash
cloop task attachments 12                                  # list task 12's files
cloop task attachments add 12 spec.md --input              # an input file for the agent
cloop task attachments add 12 bench.html --note "Before the fix"
cloop task attachments get 12 bench.html -o /tmp/bench.html # or -o - for stdout
cloop task attachments remove 12 3f2a9c1b                  # id, id prefix or name
```

The listing's ROLE column says whether each file is an `input` or a `result`.
Without `--input`, `add` attaches a file to the record, as a result. Every
subcommand accepts `--json`. `get` won't overwrite an existing file
unless you pass `--force`. Don't confuse this with `cloop task attach`, which
opens a shell inside a running task's sandbox.

## In the dashboard

A task with files shows a 📎 count in the task list and on its Kanban card.
Open the task to see them: its **Input files** first, then the **Results**,
each with its size, type, age and the person or run that added it.

To add input files, press **Add input files…** or drop files on the section.
In the Tasks tab's Add Task form, **Files** picks input files for the new task;
they are uploaded as soon as the task is created. Adding files needs
`task.mutate`. Each file is sent as the request body itself
(`POST /api/tasks/{id}/attachments?name=…`, `Content-Type:
application/octet-stream`).

- **Preview** shows a PNG, JPEG, GIF or WebP image, or a text file (plain text,
  logs, Markdown, CSV, JSON, YAML, diffs), in the page.
- **Download** saves the file under its own name.
- **Delete** asks for confirmation, then removes the file and records who did it
  in the project's audit trail. It needs `task.mutate`. Listing, previewing and
  downloading need only `project.read`, the permission that also shows the
  task's transcript.

Other types, such as HTML, SVG, PDF and archives, can only be downloaded. A file
whose bytes are not on the hub (see
[remote executors](#runs-on-remote-executors)) is listed together with the
reason.

## Runs on remote executors

How files reach the hub depends on where the agent runs:

- **On the hub's host, or in a container there**, the project directory is the
  hub's own (bind-mounted into the container), so attachments go straight into
  the project's store.
- **On an edge device, in a Kubernetes Pod, or as a containerised feature**,
  files come back in the run's result, the same document that brings back the
  run's tasks, steps and journal. A result is a single transport frame of
  limited size, so it carries at most **384 KiB** of attachments in total, in
  the order they were attached. Images and PDFs barely compress. A file that
  doesn't fit is still recorded on the hub, without its bytes and with the
  reason ("left in the executor's workspace"), so the task shows that it exists
  and where it is.

The hub checks what comes back:

- The task is identified by the hub's number for it (the hub may have
  renumbered a task the device created).
- It must still be the task the run worked on. If it was deleted or renamed on
  the hub during the run and its id now belongs to another task, nothing is
  attached.
- The bytes must match the digest sent with them. The hub scrubs them again
  with the credentials it leased and applies its own limits. A file it refuses
  is still recorded, with the reason.

A file kept on the device takes no space on the hub but counts toward the
task's 100 files. A device whose `cloop` was built before this feature returns
no attachments.

Input files go the other way. A run on the hub's host, or in a container that
mounts the project, copies them from the project's own store. A run whose
project was seeded into its sandbox (on an edge device, in a Kubernetes Pod)
has no copy of the store, so the hub dispatches it with a run session for them
(`$CLOOP_TASK_INPUTS_URL` and `$CLOOP_TASK_INPUTS_TOKEN`), and at the start of
every attempt the run fetches the task's input files from the hub
(`POST /api/run/knowledge/inputs` and `/inputs/file`). The session opens the
input files of that project's tasks and nothing else, and ends with the run.
Every file the hub serves is audited (`run.input_fetch`), and the run checks
each one against its SHA-256 before the agent sees it.

A task is named to the hub by its id and its title. A task the run created
itself, whose id the hub may have given to another task in the meantime, has no
input files. If you rename a task on the hub while a run is going, the run's
copy of it gets none of its input files, and its agent is told so. A run
fetches at most two files at a time, and the hub holds each run to about two
tasks' worth of input files in a short time. The run needs the hub's public address (`ui.external_url`) to
reach it, as it does for knowledge sources; without one the project's journal
says that the run's agents get no input files. A device whose `cloop` was built
before this feature gives its agents none.

## Where they are kept

The bytes are stored beside the project's database, one file per attachment,
named by a random id:

```text
.cloop/attachments/<32 hex characters>
.cloop/attachments/.gitignore               # "*" — never committed, even where .cloop/ is not ignored
.cloop/attachments/outbox/<task-id>/        # files waiting for the attempt to end
.cloop/attachments/inbox/<task-id>/         # the running attempt's copies of the input files
```

The metadata (name, type, size, SHA-256, role and the run) is in the
`task_attachments` table in `.cloop/state.db`. A [feature](features.md) has its
own store inside its worktree's `.cloop/`.

- **Deleting a task deletes its attachments.** Task ids are reused, and a new
  task never starts with an earlier task's files.
- **`cloop snapshot`** includes the store. **`cloop db backup`** copies only
  the database, so after restoring from it, attachments whose files it lacks
  show as missing.
- When a run starts, it removes files that no row refers to any more, after an
  hour's grace.
- **`cloop audit`** scans attachments for credentials as well as transcripts.

## Limits

| Limit | Value |
| --- | --- |
| One file | 32 MiB |
| One task | 100 files, 128 MiB |
| One project | 1 GiB |
| Carried back from a remote run | 384 KiB in total |
| Uploads in progress at once | 4 to a project, 16 to a hub process |

An upload takes its room before the first byte arrives, so uploads made at the
same time cannot together pass a limit. One that arrives slower than about
64 KiB a second is cut off.

cloop refuses a file over a limit and says which file it was. It never
truncates one.

## How the hub serves them

Attachments are written by model-authored code, and the hub serves them from
the origin the dashboard's session lives on. So it never serves one in a form
the browser would render as a document:

- A download is `application/octet-stream` with `Content-Disposition:
  attachment`, whatever the file claims to be.
- A preview (`?inline=1`) is served inline only for a PNG, JPEG, GIF or WebP
  image or for text. The check uses the bytes in the store at that moment, not
  the type recorded when the file was attached. Text is served as `text/plain`.
  SVG, HTML and PDF are never served inline.
- Every response carries `Content-Security-Policy: default-src 'none'; sandbox`
  and `X-Content-Type-Options: nosniff`.
- The hub opens the file through an `os.Root` on the store directory itself.
  It must be a regular file of the recorded size both before and after it is
  opened, and the hub serves that many bytes. On a shared-filesystem executor
  the sandbox writes the store, and this stops a link there from handing a
  viewer a file from the hub's host. Every write and removal the hub makes in
  the store goes through the same root, so swapping the store for a link
  cannot redirect those either.

An upload is the one request the hub takes as `application/octet-stream`. No
form can send that type, and a page on another origin cannot send it without a
preflight, which the hub never answers. The origin check that every
state-changing request passes applies to it too.

The routes are `GET /api/tasks/{id}/attachments`,
`POST /api/tasks/{id}/attachments` (an input file),
`GET /api/tasks/{id}/attachments/{aid}` and
`DELETE /api/tasks/{id}/attachments/{aid}`. See the
[HTTP API reference](../reference/http-api.md).
