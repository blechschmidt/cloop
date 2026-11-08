# Task attachments

A task's transcript records what an agent did. An **attachment** is a file the
agent made for a person to look at: a report, a chart, a screenshot, a data
export or a log. Attachments belong to the task and outlive the run that made
them. The dashboard shows them with the task, previews images and text, and
lets you download any of them.

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

Attaching is not audited, but the journal line names the run that did it.
Deleting is audited (`task.attachment_delete`).

## Attaching by hand

```bash
cloop task attachments 12                                  # list task 12's files
cloop task attachments add 12 bench.html --note "Before the fix"
cloop task attachments get 12 bench.html -o /tmp/bench.html # or -o - for stdout
cloop task attachments remove 12 3f2a9c1b                  # id, id prefix or name
```

Every subcommand accepts `--json`. `get` won't overwrite an existing file
unless you pass `--force`. Don't confuse this with `cloop task attach`, which
opens a shell inside a running task's sandbox.

## In the dashboard

A task with files shows a 📎 count in the task list and on its Kanban card.
Open the task to see them under **Attachments**, each with its size, type, age
and the run that made it:

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

## Where they are kept

The bytes are stored beside the project's database, one file per attachment,
named by a random id:

```text
.cloop/attachments/<32 hex characters>
.cloop/attachments/.gitignore               # "*" — never committed, even where .cloop/ is not ignored
.cloop/attachments/outbox/<task-id>/        # files waiting for the attempt to end
```

The metadata (name, type, size, SHA-256 and the run) is in the
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

The routes are `GET /api/tasks/{id}/attachments`,
`GET /api/tasks/{id}/attachments/{aid}` and
`DELETE /api/tasks/{id}/attachments/{aid}`. See the
[HTTP API reference](../reference/http-api.md).
