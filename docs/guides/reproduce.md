# Proving a commit reproduces

When you review AI-written commits, the diff shows you what changed. It doesn't
tell you whether running the same task again would give you the same change.

`cloop task reproduce` answers that question. It rebuilds the inputs a completed
task ran with, runs the task again in a fresh isolating sandbox, and compares
the commit that comes back with the one the original run produced.

```console
$ cloop task reproduce 42

IDENTICAL  task 42 — Bound the artifact reads that can OOM the hub
  the reproduction produced the same tree (3ed42031cbb2): the change is byte-for-byte reproducible

  base:     9fbc1f2a3e4d5c6b7a8f9e0d1c2b3a4f5e6d7c8b
  original: 4a1b2c3d4e5f60718293a4b5c6d7e8f901a2b3c4 → tree 3ed42031cbb2…
  replay:   77e5d4c3b2a1908f7e6d5c4b3a29180f7e6d5c4b → tree 3ed42031cbb2…
  executor: container-1 (container, isolation=container)

  took 6m12s
```

## What it is not

It is not [`cloop task replay`](../../README.md), which re-sends a prompt to a
different model and scores the two transcripts for word overlap. That says
something about models but nothing about code: a model can describe a change
it did not make in almost the same words, and two correct implementations can
share almost no prose. Reproduce compares tree hashes and test results, and
never scores text.

## The four verdicts

| Verdict | Means |
| --- | --- |
| `IDENTICAL` | Same git tree hash. The strongest result, and no tests need to run. |
| `EQUIVALENT` | Different bytes, but the project's own test command passes on both trees. |
| `DIVERGENT` | A different change. The diff-of-diffs is attached. |
| `INCONCLUSIVE` | No verdict could be reached. |

Verdicts compare tree hashes, not commit SHAs. Two runs always produce
different commits (different timestamps, different parents), so comparing SHAs
would report `DIVERGENT` for every successful reproduction.

`INCONCLUSIVE` means cloop could not decide. It keeps the other verdicts
meaningful: a `DIVERGENT` verdict on a task that touched no external state
points to nondeterminism you should investigate, and that only helps if
`DIVERGENT` is rare. Reporting "the project has no test command" or "the
sandbox image moved" as `DIVERGENT` would bury the real findings in noise.

You get `INCONCLUSIVE` when:

- the project has no test command `cloop` can detect, so equivalence can't be
  decided. Give the project a test harness cloop can detect and leave
  `--skip-tests` off, or accept that only `IDENTICAL` is possible.
- the base commit could not be recovered reliably (see below).
- the sandbox could not run, or the test command could not run on one of the
  trees.

## Why equivalence is gated on your tests, not on an AI

A language model asked whether two diffs are equivalent will confidently say
yes. A test suite that passes on both trees is a fact. So `EQUIVALENT`
requires the project's own test command (`go test ./...`, `pytest`,
`npm test`, or whatever `cloop test` detects) to pass on the original tree
*and* on the reproduced one, each in a sandbox of the same kind.

A suite that fails on both trees is not equivalence. The failures can have
unrelated causes, and calling a broken change faithfully reproduced would be
the worst answer this command could give.

## What gets reconstructed

No single record holds a task's full provenance. Each input was recorded by the
subsystem that produced it, and reproduce reads all five:

| Input | Recovered from |
| --- | --- |
| provider, model, effort, goal, instructions | project state |
| the rendered prompt | `pm.ExecuteTaskPrompt`, the same call the orchestrator made |
| the sandbox (executor, image digest, spec hash) | the task artifact's frontmatter stamp |
| the returned commit | the task record, written by `pkg/writeback` |
| the commit it was based on | the `write_back` event's detail blob |

If an input is missing, the verdict carries a warning about it.

### The base commit

The base commit has to be right. If a reproduction starts from a tree that
already contains part of the change, reaching the same tree proves very little.

cloop takes the base from one of three sources, most trusted first:

1. **recorded**: the `write_back` event names the commit the executor was
   provisioned at. Trusted.
2. **fork-point**: the merge base of `HEAD` and the returned commit, which is
   where the write-back branch diverged. Correct for a write-back of any
   length. Trusted.
3. **first-parent**: the parent of the returned commit. This is only correct if
   the write-back was a single commit, and nothing available can confirm that.
   Never trusted: the verdict is capped at `INCONCLUSIVE`.

## Which tasks can be reproduced

Only tasks with a recorded write-back commit, which means tasks that ran on an
**isolating executor**. A task that ran on the host committed straight into the
working tree, so it has no commit of its own to compare against. For those
tasks the **Reproduce** button in the task detail modal is disabled, and its
tooltip gives the reason.

## The non-destructive contract

A reproduction never changes the project it checks. Three separate mechanisms
enforce this:

- **Never writes back.** The sandbox spec asks for *bundle* mode, so the work
  comes back as data and nothing is pushed. No ref can move anywhere.
- **Never touches your refs.** The comparison reads the project's object store
  through `objects/info/alternates`, which it can only read, and does every git
  operation that writes in a scratch repository under `/tmp`. Your branches,
  `HEAD` and uncommitted edits stay as you left them.
  (`TestCompareBundleLeavesTheProjectAlone` checks this on a real repository
  with a dirty working tree.)
- **Never runs on the host.** cloop refuses a host-sharing executor, because a
  reproduction there would test your working tree instead of the recorded
  commit.

Reproductions have their own quota, `max_concurrent_reproductions`, separate
from `max_concurrent_tasks`, so a burst of them slows other reproductions but
not the tenant's real work. See [the security model](../security/model.md).

## In the web UI

The task detail modal has a **Reproduce** button next to **Edit**, and a
Reproduction section that lists every past verdict for the task.

| Route | Permission |
| --- | --- |
| `GET /api/tasks/{id}/provenance` | `project.read` |
| `GET /api/tasks/{id}/reproductions` | `project.read` |
| `GET /api/reproductions/{id}` | `project.read` |
| `POST /api/tasks/{id}/reproduce` | `run.start` |

The reads need `project.read` because a verdict is about code the caller can
already see; an auditor who can read a project but not change it is the main
audience. The POST needs `run.start` because it makes the fleet run a model
and a test suite.

In strict no-host-execution mode, the provenance and reproduce routes refuse
with an error. The agent never runs on the host, but rebuilding the prompt runs
`git diff` for repository context, and resolving and comparing commits runs
read-only git plumbing on the control plane. That is host execution, so it is
blocked like every other such path. On a strictly isolated hub, run
`cloop task reproduce` on the hub host instead. Moving the comparison into a
sandbox of its own would remove this restriction.

## Flags

| Flag | Effect |
| --- | --- |
| `--show-diff` | Print the full diff-of-diffs instead of its `--stat` summary. |
| `--json` | Print the whole verdict record as JSON. |
| `--timeout 20m` | Time limit for the reproduction. Default 45m. |
| `--skip-tests` | Skip the test comparison. A result that isn't identical can then only be `INCONCLUSIVE`. |
| `--no-save` | Do not record the verdict in the project's database. |

Verdicts are stored in the `reproductions` table of the project's
`.cloop/state.db`. If you reproduce every task in a release, you can query the
results afterwards without running them again.

## A floating image tag weakens the answer

If the original run used `image: python:3.12` instead of a digest, six weeks
later that tag can resolve to a different filesystem. A `DIVERGENT` verdict
may then come from the image changing, not from a nondeterministic agent, and
the verdict carries a warning that says so. If you plan to rely on
reproduction, pin digests in `.cloop/sandbox.yaml`. See
[the executor architecture](../architecture/executors.md).
