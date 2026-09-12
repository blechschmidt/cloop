# Proving a commit reproduces

A team reviewing a hundred AI-authored commits can read every diff and still not
know the thing that matters most: **if I run this task again, do I get the same
change?**

`cloop task reproduce` answers it. It reconstructs a completed task's exact
input state, re-runs it in a fresh isolating sandbox, and compares the commit
that comes back against the one the original run produced.

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

It is not [`cloop task replay`](../../README.md). That command re-sends a
prompt to a different model and scores the two **transcripts** for word overlap.
That is a useful signal about models and no signal at all about code: a model
can write a near-identical explanation of a change it did not make, and two
correct implementations of the same task share almost no prose.

Reproduce compares tree hashes and test outcomes. Nothing in it scores text.

## The four verdicts

| Verdict | Means |
| --- | --- |
| `IDENTICAL` | Same git tree hash. The strongest result; no test run needed. |
| `EQUIVALENT` | Different bytes, but the project's own test command passes on **both** trees. |
| `DIVERGENT` | A different change. The diff-of-diffs is attached. |
| `INCONCLUSIVE` | No verdict could be reached. |

Tree hashes, not commit SHAs: two runs always produce different commits
(different timestamps, different parents), so comparing SHAs would report
`DIVERGENT` for every reproduction that ever succeeded.

`INCONCLUSIVE` is not a fourth opinion about the code — it is the refusal to
have one, and it exists to protect the other three. The reason to run this at
all is that **a `DIVERGENT` verdict on a task that touched no external state is
a precise signal of nondeterminism worth investigating.** That signal is only
worth chasing if `DIVERGENT` is rare and means something. Folding "the project
has no test command" or "the sandbox image moved" into `DIVERGENT` would bury
every real finding under noise.

You will see `INCONCLUSIVE` when:

- the project has no test command `cloop` can detect, so equivalence cannot be
  decided (pass one with `--skip-tests` off and a detectable harness, or accept
  `IDENTICAL`-or-nothing);
- the base commit could not be recovered reliably — see below;
- the sandbox could not run, or the test command could not execute on a tree.

## Why equivalence is gated on your tests, not on an AI

An LLM asked "are these two diffs equivalent?" will confidently say yes. A test
suite that passes on both trees is a fact. So `EQUIVALENT` requires the
project's own command — `go test ./...`, `pytest`, `npm test`, whatever
`cloop test` detects — to pass on the original tree *and* on the reproduced one,
each run inside a sandbox of the same kind.

"Both suites fail" is deliberately **not** equivalence. Two suites can fail for
unrelated reasons, and certifying a broken change as faithfully reproduced is
the worst answer this tool could give.

## What gets reconstructed

There is no single provenance row to read. Each link of the chain was recorded
by the subsystem that formed it, and reproduce reads all five:

| Input | Recovered from |
| --- | --- |
| provider, model, effort, goal, instructions | project state |
| the rendered prompt | `pm.ExecuteTaskPrompt` — the same call the orchestrator made |
| the sandbox (executor, image digest, spec hash) | the task artifact's frontmatter stamp |
| the returned commit | the task record, written by `pkg/writeback` |
| the commit it was based on | the `write_back` event's detail blob |

Anything missing becomes a warning on the verdict rather than a silent gap,
because a verdict is only worth what its inputs were.

### The base commit

The base is the one input that must be right. A reproduction that started from a
tree already containing part of the change is not evidence about the change:
reaching the same tree is easy when most of it is already there.

Three sources, in descending order of trust:

1. **recorded** — the `write_back` event says which commit the executor
   provisioned at. Trusted.
2. **fork-point** — the merge base of `HEAD` and the returned commit, i.e.
   where the write-back branch diverged. Correct for a write-back of any
   length. Trusted.
3. **first-parent** — the parent of the returned commit. Correct only if the
   write-back was a single commit, and nothing available can confirm it was.
   **Never trusted**: the verdict is capped at `INCONCLUSIVE`.

## Which tasks can be reproduced

Only tasks with a recorded write-back commit — that is, tasks that ran on an
**isolating executor**. A task that ran on the host committed straight into the
working tree, so it has no commit of its own to compare against. The Reproduce
button in the task detail modal is disabled for those, with the reason in its
tooltip.

## The non-destructive contract

A verification tool that can damage what it verifies is worse than no tool. The
contract is enforced in three separate places, not documented in one:

- **Never writes back.** The sandbox spec asks for *bundle* mode, so the work
  comes home as bytes. There is no push, so no ref anywhere can move.
- **Never touches your refs.** The comparison borrows the project's object
  store through `objects/info/alternates` — read-only by construction — and does
  every mutating git operation in a scratch repository under `/tmp`. Your
  branches, your `HEAD`, and your uncommitted edits come back exactly as you
  left them. (`TestCompareBundleLeavesTheProjectAlone` asserts this on a real
  repository with a dirty working tree.)
- **Never runs on the host.** A host-sharing executor is refused, not silently
  used; a reproduction there would score your working tree instead of the
  recorded commit.

It also runs under its own quota, `max_concurrent_reproductions`, separate from
`max_concurrent_tasks` — so a reproduction storm slows reproductions and not the
tenant's real work. See [the security model](../security/model.md).

## In the web UI

The task detail modal has a **Reproduce** button next to Edit, and a
Reproduction section listing every past verdict for that task.

| Route | Permission |
| --- | --- |
| `GET /api/tasks/{id}/provenance` | `project.read` |
| `GET /api/tasks/{id}/reproductions` | `project.read` |
| `GET /api/reproductions/{id}` | `project.read` |
| `POST /api/tasks/{id}/reproduce` | `run.start` |

The reads are `project.read` because a verdict is a statement about code the
caller can already see — an auditor who can read a project but not change it is
exactly who this is for. The POST is `run.start` because it makes the fleet
execute a model and a test suite.

**Under strict no-host-execution mode these two routes refuse.** The agent still
never runs on the host, but reconstructing the prompt shells out to `git diff`
for repository context, and resolving and comparing commits runs read-only git
plumbing on the control plane. That is host execution, so it is gated like every
other such path. On a strictly-isolated hub, run `cloop task reproduce` on the
hub host instead. Moving the comparison into a sandbox of its own would lift the
restriction and is the obvious next step for this subsystem.

## Flags

| Flag | Effect |
| --- | --- |
| `--show-diff` | Print the full diff-of-diffs, not just its `--stat` summary. |
| `--json` | Emit the whole verdict record as JSON. |
| `--timeout 20m` | Bound the reproduction. Default 45m. |
| `--skip-tests` | Skip the behavioural gate. A non-identical result can then only be `INCONCLUSIVE`. |
| `--no-save` | Do not record the verdict in the project's database. |

Verdicts are stored in the `reproductions` table of the project's
`.cloop/state.db`, so a sweep across a release can be queried afterwards rather
than re-run.

## A floating image tag weakens the answer

If the original ran from `image: python:3.12` rather than a digest, six weeks
later that tag resolves to a different filesystem. A `DIVERGENT` verdict may
then be the image moving rather than the agent being nondeterministic — so the
verdict carries a warning saying so. Pin digests in `.cloop/sandbox.yaml` if you
intend to rely on reproduction; see
[the executor architecture](../architecture/executors.md).
