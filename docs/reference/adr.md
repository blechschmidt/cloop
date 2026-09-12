# Decision records

`cloop adr` keeps Architectural Decision Records: one file per significant
design choice, holding the context that forced it, the decision itself, and the
consequences that follow.

Records live in `.cloop/adr/` as markdown with YAML frontmatter, so they review
in a pull request like any other change and travel with the repository rather
than with whoever remembers the discussion.

## Why this is not the journal

cloop has two places a rationale can go, and they answer different questions.

| | [Task journal](commands.md) (`cloop task journal`) | Decision record (`cloop adr`) |
|---|---|---|
| Scope | One task | The project |
| Lifetime | As long as the task is interesting | Outlives every task that motivated it |
| Shape | Append-only entries | One document with a status |
| Question | "Why did this task go the way it did?" | "Why is the system built this way?" |

A journal entry explaining that a task switched from polling to a watcher is
useful for a week. That the project uses SQLite with WAL as its single state
store — and what was given up to get there — is worth a record that a reader
finds two years later, still says who decided it, and says whether it still
holds.

## The lifecycle

A decision is never edited away. It moves through a status, and a reversal is
recorded as a new record that supersedes the old one:

- `Proposed` — written, not yet agreed. The default for a new record.
- `Accepted` — in force. This is what the system does.
- `Deprecated` — no longer the way to do things, with no direct replacement.
- `Superseded` — replaced by a later record, which is linked from this one.
- `Rejected` — considered and declined. Worth keeping: it stops the same
  proposal arriving again with the same answer.

Keeping the losing record is the point. The reason a decision was reversed is
usually more valuable than the decision, and deleting it leaves the next reader
to rediscover the constraint the hard way.

## Commands

```
cloop adr new <title>            Create a record (Proposed by default)
cloop adr list                   List records, oldest first
cloop adr show <id>              Print one record with its metadata
cloop adr status <id> <status>   Move a record through the lifecycle
cloop adr supersede <new> <old>  Record that one decision replaces another
```

`new` accepts `--deciders` and `--tags` as comma-separated lists, `--status` to
open a record at something other than `Proposed`, and `--body` for the markdown
body — `--body -` reads it from stdin, which is how to pipe in a record written
in an editor. With no body, a template with Context / Decision / Consequences /
Alternatives Considered sections is used.

`list` takes `--status` to filter and `--json` for machine-readable output;
`show` takes `--json`. A status is matched case-insensitively and anything
outside the five values above is refused, so a typo cannot be persisted as a
sixth status that every filter then misses.

## A worked example

```console
$ cloop adr new "Use SQLite for state" --deciders alice,bob --tags storage
Created ADR-0001: Use SQLite for state
.cloop/adr/0001-use-sqlite-for-state.md

$ cloop adr status 1 accepted
ADR-0001 is now Accepted
```

A year later the decision changes. Write the new record and link it; the old
one is not touched by hand:

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

`supersede` writes both files: the new record gains a `supersedes` link, and the
old one gains the reverse link and moves to `Superseded`. Both directions are
stored so a reader arriving at either record can find the other.

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

Every field except `id` and `title` is optional, and a file with no frontmatter
at all still lists — the id and title are then read from the filename, which is
`<zero-padded-id>-<slug>.md`. That keeps a record written by hand, or by a
generator that predates this command, from being silently ignored.

Writes are atomic (staged in a sibling temporary file, then renamed), so an
interrupted status change cannot leave half-written frontmatter that would drop
the record from every listing.

The implementation is [`pkg/adr/adr.go`](../../pkg/adr/adr.go).
