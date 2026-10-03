# Done means committed

An agent's `TASK_DONE` is its own word. With **done means committed** on, a
project holds every task to something it can check: the changes the task made
are committed — and, optionally, **pushed** to the upstream of the branch they
are on. A task whose agent says it is finished while its work still sits
uncommitted in the working tree is not finished, whatever it said.

It is off by default, and per project.

## Why it exists

An agent that starts a test suite or a review in the background and ends its
turn with "I'll address what it finds, then commit and push" behaves as it
would in an interactive session, where something wakes it when the job ends. A
cloop run is not interactive: ending the turn ends the task. cloop already hands
a turn back when the final message *says* the agent is waiting
([concepts](../getting-started/concepts.md#the-signal-protocol)), but that is
phrase matching, and new wordings slip past it. Task 20368 in cloop's own
ledger ended

> The commit message is drafted. The only thing still running is the
> adversarial review agent. I'll address what it finds, re-run `-race` on the
> touched packages, then commit and push.

— nothing matched, the task was recorded done, and 24 changed paths sat
uncommitted for the next task to trip over. Whatever the wording, every such
turn leaves the same thing behind: a working tree that still holds the task's
changes. Done means committed checks that instead of the words.

## Turning it on

In the dashboard, open a project's **Overview**. Under *Active Options*:

| Badge | Meaning |
|---|---|
| 📌 **Done = Committed** | A task is done only once its changes are committed. |
| 🚀 **…and Pushed** | Its commits must also be on the branch's upstream. Turning this on turns the check on too; turning *Done = Committed* off keeps the choice for next time. |

From the command line, in the project directory:

```bash
cloop require-committed              # show the setting
cloop require-committed committed    # done means committed
cloop require-committed pushed       # ... and pushed
cloop require-committed off

cloop run --require-committed            # set it, then run
cloop run --require-committed=pushed
cloop status                             # shows "Done: only once committed and pushed"
```

The setting is stored in the project's state, not in `config.yaml` — the way the
[review gate](review-gate.md)'s is — so it travels with the project to an
[isolating executor](../architecture/executors.md), and a run that is already
going picks up a change at its next task.

## What happens during a task

1. **As an attempt starts**, cloop records what the repository holds: every
   path `git status` reports, with a fingerprint of each (its index entry and
   its working-tree content), and the commit `HEAD` names.
2. **The agent works as usual.**
3. **When its turn ends** — with `TASK_DONE`, or without a signal but otherwise
   acceptable as done — cloop compares. Outstanding is:
   - every path this attempt changed and left uncommitted: new, modified,
     deleted, staged, renamed or conflicted;
   - with *pushed*, every commit this attempt made on `HEAD` that `HEAD`'s
     upstream does not have.
4. **Anything outstanding hands the turn back** — in the same conversation when
   the provider can resume one (`claudecode` does), at most twice — with a
   message naming exactly the paths and commits, and saying to finish and
   commit (and push) them, or to revert them deliberately:

   ```
   Your turn ended, but this project counts a task as done only once its work
   is committed and pushed to its branch's upstream — and yours is not yet.

   These changes of this task are not committed (as `git status --short` shows them):
     ?? pkg/redact/registry.go
      M pkg/audit/audit.go
   ...
   ```

5. **A turn that still ends that way** is an `uncommitted_work` abort: the task
   goes back to `pending`, not `done`.

Nothing in this ever reverts, stashes or commits the agent's work. The check
only reads the repository — git runs with optional locks off, so even reading
the status does not rewrite the index behind the agent's back — and the work
stays exactly where the agent left it.

### What is never the task's

- **What was already there.** A path that was dirty when the attempt started
  and is unchanged since — an operator's own edits, `cloop init`'s addition to
  `.gitignore`, a tree a crashed run left behind — is not blamed on the task,
  and the agent is told to leave it alone. Changing such a path further, or
  staging it, makes it the task's.
- **Commits that were already local.** With *pushed*, only commits the attempt
  made count; commits that were on `HEAD` but not pushed when it started are not
  its to publish.
- **cloop's own directory.** `.cloop/` — its state, artifacts, the
  [parallel task worktrees](../reference/commands.md) and the
  [feature worktrees](features.md) under `.cloop/features/` — is never checked,
  whether or not the repository ignores it.

### The next attempt is held to the same work

An aborted attempt leaves its changes in the tree, so the next attempt finds
them already there when it starts — and would count them as somebody else's.
cloop records the paths an attempt was blamed for, and the `HEAD` it started
at, in `.cloop/artifacts/<task-id>_uncommitted.json`, and the next attempt at
the same task is held to them. The record is removed once the task's work is
committed, and ignored after seven days.

### Bounded

The hand-back shares its limit with the [unfinished-turn
hand-back](../getting-started/concepts.md#the-signal-protocol): at most two per
attempt, together. The abort counts towards the run's consecutive-abort ceiling
(`--max-failures`, default 3), the same bound every abort has: an aborted task
is retried after a short wait, and when the ceiling is reached on an
`uncommitted_work` abort the run **pauses** with the reason *work left
uncommitted* rather than looping. The dashboard shows the pause; the event
journal has a `task_aborted` row per attempt — with the paths, the unpushed
commits and the upstream — and a `session_paused` row. Commit or revert the
work, then start the run again.

## Pushing

With *pushed*:

- **No upstream, nothing to check.** A branch without an upstream — a parallel
  task's worktree branch, a feature branch, a detached `HEAD` — is noted on the
  task ("branch … has no upstream: the push was not checked") rather than
  failed. Give the branch an upstream (`git push -u`) if you want it checked.
- **The review gate's held pushes are pending, not missing.** With the
  [review gate](review-gate.md) on, the agent's pushes are held until the
  reviewer approves, then sent by cloop. A commit a held push covers counts as
  pending and does not hand the turn back. If the gate cannot hold pushes on
  this machine, it tells the agent not to push at all, and the push is not
  checked.
- **The check runs before the review.** A task whose work is not finished is
  not reviewed and its held pushes are not sent; the gate's own fix turns are
  checked the same way afterwards.
- **A push that cannot succeed** — a read-only grant, a branch-restricted
  [GitHub grant](secrets.md) that excludes the branch — will keep the task from
  ever being done. Use *committed* for such a project.

## Where the check runs

The check runs where the work is:

| Run | Checked in |
|---|---|
| Sequential | the project's working directory |
| Parallel with `--worktree-parallel` | each task's own worktree under `.cloop/worktrees/` |
| Parallel in one shared tree | **not checked** when tasks run side by side: their changes cannot be told apart, so each would be blamed for the others'. The task is annotated; use `--worktree-parallel`. |
| A [feature](features.md) | the feature's own worktree, against its own setting |
| An isolating executor | inside the sandbox, by the `cloop run` there: the setting arrives with the project |

A task worktree whose attempt ended with work uncommitted is **kept** (locked
with `git worktree lock`) instead of removed, since its branch holds only what
was committed; the next attempt reopens it as it was left. `cloop worktree
prune` and the hub's startup sweep leave locked worktrees alone.

A project directory that is not a git repository is not checked; the run says so
for each task.

An older `cloop` inside a sandbox or on an edge device ignores the setting, as
it ignores any field it does not know — upgrade it.

## Recovery

When a run dies while a turn is handed back, its agent's `TASK_DONE` must not
be what stale-task recovery adopts. The hand-back records the attempt as
`pending` (reason `uncommitted_work`) in the task's verdict sidecar,
`.cloop/artifacts/<id>_verdict.json`, which recovery reads before the agent's
own signal; the abort records it again before it is announced. Recovery
re-queues such a task. With the [review gate](review-gate.md) on, the gate's
pending verdict already keeps an unreviewed `TASK_DONE` from being adopted.

The janitor removes `<id>_uncommitted.json` records once they are a week old,
the age past which they are ignored anyway.
