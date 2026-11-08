# Decision records

`cloop adr` keeps Architectural Decision Records (ADRs). Each record is a file
about one significant design choice: the context that led to it, the decision,
and its consequences.

Records live in `.cloop/adr/` as Markdown with YAML frontmatter, so you review
them in pull requests like any other change.

## Why this is not the journal

cloop has two places to record why something was done, and they answer
different questions.

| | [Task journal](commands.md) (`cloop task journal`) | Decision record (`cloop adr`) |
|---|---|---|
| Scope | One task | The project |
| Lifetime | As long as the task is relevant | Outlives the tasks that led to it |
| Shape | Append-only entries | One document with a status |
| Question | "Why did this task go the way it did?" | "Why is the system built this way?" |

A journal entry explaining that a task switched from polling to a file watcher
is useful for a week or so. A decision such as using SQLite with WAL as the only
state store belongs in a record, which tells a reader two years later who made
it, what was given up for it, and whether it still holds.

## The lifecycle

You don't delete or rewrite a decision. You change its status, and you record a
reversal as a new record that supersedes the old one. The statuses are:

- `Proposed`: written but not yet agreed. New records start here.
- `Accepted`: in force. The system works this way.
- `Deprecated`: no longer how things are done, and nothing directly replaces it.
- `Superseded`: replaced by a later record, which this one links to.
- `Rejected`: considered and declined. Keeping it saves the next person from
  proposing the same thing and getting the same answer.

Keep superseded and rejected records. The reason a decision was reversed is
often more useful than the decision itself, and without the record the next
reader has to rediscover the constraint.

## Commands

```
cloop adr new <title>            Create a record (Proposed by default)
cloop adr list                   List records, oldest first
cloop adr show <id>              Print one record with its metadata
cloop adr status <id> <status>   Move a record through the lifecycle
cloop adr supersede <new> <old>  Record that one decision replaces another
```

`new` accepts `--deciders` and `--tags` as comma-separated lists, `--status` to
start a record at a status other than `Proposed`, and `--body` for the Markdown
body. `--body -` reads the body from stdin, so you can pipe in a record you
wrote in an editor. Without a body, the record gets a template with Context,
Decision, Consequences and Alternatives Considered sections.

`list` takes `--status` to filter and `--json` for machine-readable output, and
`show` takes `--json`. Statuses are case-insensitive. Any value other than the
five above is refused with an error, so a typo can't be saved as a sixth status
that no filter would match.

## A worked example

```console
$ cloop adr new "Use SQLite for state" --deciders alice,bob --tags storage
Created ADR-0001: Use SQLite for state
.cloop/adr/0001-use-sqlite-for-state.md

$ cloop adr status 1 accepted
ADR-0001 is now Accepted
```

A year later the decision changes. Write a new record and link the two. You
don't edit the old record by hand:

```console
$ cloop adr new "Move state to Postgres"
Created ADR-0002: Move state to Postgres

$ cloop adr supersede 2 1
ADR-0002 supersedes ADR-0001

$ cloop adr list
ID    STATUS      DATE        TITLE
0001  Superseded  2026-03-01  Use SQLite for state (superseded by ADR-0002)
0002  Proposed    2027-04-11  Move state to Postgres
```

`supersede` updates both files. The new record gets a `supersedes` link, and
the old one gets the reverse link and moves to `Superseded`. Because both links
are stored, a reader who opens either record can find the other.

## File format

```markdown
---
id: 1
title: "Use SQLite for state"
status: Accepted
date: 2026-03-01
deciders: ["alice", "bob"]
tags: ["storage"]
superseded_by: [2]
---

# ADR-0001: Use SQLite for state

## Context
...
```

Every field except `id` and `title` is optional. A file with no frontmatter at
all is still listed: cloop reads the id and title from the filename, which has
the form `<zero-padded-id>-<slug>.md`, so records written by hand or by older
tools aren't skipped.

Writes are atomic (a temporary file next to the record, then a rename), so an
interrupted status change can't leave half-written frontmatter that would drop
the record from listings.

The implementation is [`pkg/adr/adr.go`](../../pkg/adr/adr.go).
