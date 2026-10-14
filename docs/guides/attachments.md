# Task attachments

A task's transcript says what an agent did. An **attachment** is what it made
for a person to look at: a report, a chart, a screenshot, a data export, a log.
Attachments belong to the task, survive the run that made them, and are shown
with the task in the dashboard — previewed when they are images or text, and
downloadable whatever they are.

## How a run attaches a file

Every attempt at a task gets an **outbox**, a directory the agent is told about
in its prompt and in its environment:

```text
.cloop/attachments/outbox/<task-id>/        # absolute path in $CLOOP_TASK_ATTACHMENTS
```

The agent copies files into it — `cp report.html "$CLOOP_TASK_ATTACHMENTS"/`,
or a script that writes its plot there directly. When the attempt ends, cloop
moves every regular file it finds there into the task's attachments and empties
the outbox. Subdirectories are kept as part of the name, so
`plots/loss.png` is attached as `plots/loss.png`. `$CLOOP_TASK_ID` names the
task.

That is all an agent needs; it does not have to run any command, which matters
because the `cloop` on an agent's `PATH` is not necessarily the build running
the task. The outbox is offered to agents that work in the project with tools
of their own (Claude Code); a provider that only returns text is not told about
one.

What happens to each file when the attempt ends:

| The file is… | Then |
| --- | --- |
| a regular file within the [limits](#limits) | attached; its bytes are scrubbed of the credentials leased to the run, as the transcript is |
| a symbolic link | not followed and not attached — copy the file itself |
| a FIFO, device or socket | not read, not attached |
| nested more than 8 directories deep, or past the 1000th entry | not looked at |
| over a limit | not attached |

The outbox is emptied of everything it handled, attached or refused, and the
project's **Event History** gets one `task_attachments` line naming what was
attached and what was not, and why. A file that failed for a reason that may
pass — a full disk, a busy database — stays in the outbox and is tried again.

Attachments are collected when an attempt finishes, fails, times out or is
aborted — a timed-out benchmark's partial results are still its results. An
attempt that ended some other way — the run was stopped, paused or died — is
collected when the run loop exits, or else when the task's next attempt
starts; either way the files are credited to the run that made them. A task
that is deleted takes its outbox with it, so a new task given its id never
starts with someone else's files.

Attaching is not an audited action; the journal line names the run that did
it. Deleting one is (`task.attachment_delete`).

## Attaching by hand

```bash
cloop task attachments 12                                  # list task 12's files
cloop task attachments add 12 bench.html --note "Before the fix"
cloop task attachments get 12 bench.html -o /tmp/bench.html # or -o - for stdout
cloop task attachments remove 12 3f2a9c1b                  # id, id prefix or name
```

Every subcommand takes `--json`. `get` refuses to overwrite an existing file
without `--force`. This is not `cloop task attach`, which opens a shell inside a
running task's sandbox.

## In the dashboard

A task with files carries a 📎 count in the task list and on its Kanban card.
Open the task and its details list them under **Attachments**, each with its
size, type, age and the run that made it:

- **Preview** shows a PNG, JPEG, GIF or WebP image, or a text file (plain text,
  logs, Markdown, CSV, JSON, YAML, diffs), in place.
- **Download** saves the file under its own name.
- **Delete** asks first, then removes the file and records who did it in the
  project's audit trail. It needs `task.mutate`; listing, previewing and
  downloading need only `project.read`, the permission that shows the task's
  transcript.

Anything else — HTML, SVG, PDF, archives — is offered as a download only. A
file whose bytes are not on the hub (see [remote executors](#runs-on-remote-executors))
is listed with the reason.

## Runs on remote executors

Where the agent runs decides how its files reach the hub:

- **On the hub's host, or in a container there**, the project directory is the
  hub's own (bind-mounted into the container), so attachments land in the
  project's store directly.
- **On an edge device, in a Kubernetes Pod, or as a containerised feature**,
  files come back in the run's result — the same document that brings back its
  tasks, steps and journal. A result is one bounded transport frame, so it
  carries at most **384 KiB** of attachments in total, in the order they were
  attached; images and PDFs barely compress. A file that does not fit is still
  recorded on the hub, without its bytes and with the reason ("left in the
  executor's workspace"), so the task shows it exists and where it is.

The hub checks what comes back: the task is the hub's number for it (a task the
device created may have been renumbered), and it must still be the task the run
worked on — one deleted or renamed on the hub while the run was out, whose id
now belongs to another task, gets nothing. The bytes must match the digest sent
with them, they are scrubbed again with what the hub leased, and the hub's own
limits apply; a file the hub refuses is still recorded, saying why. A file kept
on the device takes no room on the hub, but counts toward the task's 100 files.
A device only sends what its `cloop` knows how to: one built before this
feature returns no attachments.

## Where they are kept

The bytes live beside the project's database, one file per attachment, named
by a random id:

```text
.cloop/attachments/<32 hex characters>
.cloop/attachments/.gitignore               # "*" — never committed, even where .cloop/ is not ignored
.cloop/attachments/outbox/<task-id>/        # files waiting for the attempt to end
```

What describes them — name, type, size, SHA-256, the run — is the
`task_attachments` table in `.cloop/state.db`. A
[feature](features.md) has a store of its own inside its worktree's `.cloop/`.

- **Deleting a task deletes its attachments.** Task ids are reused; a new task
  never opens with a predecessor's files.
- **`cloop snapshot`** includes the store; **`cloop db backup`** copies the
  database only, so a restore from it lists attachments whose files it does not
  have — they show as missing.
- A run's start removes files no row names any more, after an hour's grace.
- **`cloop audit`** scans attachments for credentials along with the transcripts.

## Limits

| Limit | Value |
| --- | --- |
| One file | 32 MiB |
| One task | 100 files, 128 MiB |
| One project | 1 GiB |
| Carried back from a remote run | 384 KiB in total |

A file over a limit is refused and named, never truncated.

## How the hub serves them

An attachment is written by a run — by model-authored code — and the hub serves
it from its own origin, the one the dashboard's session lives on. So nothing is
ever served to be rendered as a document:

- A download is `application/octet-stream` with `Content-Disposition:
  attachment`, whatever the file claims to be.
- A preview (`?inline=1`) is served inline only for a PNG, JPEG, GIF or WebP
  image or for text, judged on the bytes in the store at that moment rather
  than on the type recorded when it was attached. Text is served as
  `text/plain`. SVG, HTML and PDF are never inline.
- Every response carries `Content-Security-Policy: default-src 'none'; sandbox`
  and `X-Content-Type-Options: nosniff`.
- The file is reached through an `os.Root` opened on the store directory itself,
  and must be a regular file both before and after it is opened, with the size
  recorded for it; exactly that many bytes are served. On a shared-filesystem
  executor the store is written from inside the sandbox, so a link there must
  not hand a viewer a file from the hub's host — and every write and removal
  the hub makes in the store goes through the same root, so a store swapped for
  a link cannot redirect them either.

The routes are `GET /api/tasks/{id}/attachments`,
`GET /api/tasks/{id}/attachments/{aid}` and
`DELETE /api/tasks/{id}/attachments/{aid}`; see the
[HTTP API reference](../reference/http-api.md).
