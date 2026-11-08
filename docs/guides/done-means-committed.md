# Done means committed

An agent's `TASK_DONE` is only its own claim. When **done means committed** is
on, a task also has to pass a check cloop can run itself: the changes the task
made must be committed and, optionally, **pushed** to the upstream of their
branch. If the agent says it has finished but its work is still uncommitted in
the working tree, the task is not done.

The setting is per project and off by default.

## Why it exists

Sometimes an agent starts a test suite or a review in the background and ends
its turn with "I'll address what it finds, then commit and push". In an
interactive session that works, because something wakes the agent when the job
ends. A cloop run is not interactive: ending the turn ends the task. cloop
already hands a turn back when the final message *says* the agent is waiting
([concepts](../getting-started/concepts.md#the-signal-protocol)), but that
relies on matching phrases, and new wordings get past it. One task in cloop's
own ledger ended like this:

> The commit message is drafted. The only thing still running is the
> adversarial review agent. I'll address what it finds, re-run `-race` on the
> touched packages, then commit and push.

No phrase matched, the task was recorded as done, and 24 changed paths were
left uncommitted for the next task to trip over. Whatever the wording, such a
turn always leaves a working tree that still holds the task's changes, and that
is what done means committed checks.

## Turning it on

In the dashboard, open a project's **Overview**. Under *Active Options*:

| Badge | Meaning |
|---|---|
| 📌 **Done = Committed** | A task is done only once its changes are committed. |
| 🚀 **…and Pushed** | Its commits must also be on the branch's upstream. Turning this on also turns on the commit check. Turning *Done = Committed* off remembers this choice for next time. |

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

The setting is stored in the project's state, like the
[review gate](review-gate.md)'s, and not in `config.yaml`. That way it travels
with the project to an [isolating executor](../architecture/executors.md), and
a run that is already going picks up a change at its next task.

## What happens during a task

1. **When an attempt starts**, cloop records the state of the repository: every
   path `git status` reports, with a fingerprint of each (its index entry and
   its working-tree content), and the commit `HEAD` points to.
2. **The agent works as usual.**
3. **When its turn ends**, with `TASK_DONE` or with no signal but otherwise
   acceptable as done, cloop compares. These count as outstanding:
   - every path this attempt changed and left uncommitted: new, modified,
     deleted, staged, renamed or conflicted;
   - with *pushed*, every commit this attempt made on `HEAD` that `HEAD`'s
     upstream does not have.
4. **If anything is outstanding, cloop hands the turn back**, at most twice,
   and in the same conversation when the provider can resume one (`claudecode`
   can). The message lists the paths and commits and tells the agent to finish
   and commit (and push) them, or to revert a change that should not be kept
   and say so:

   ```
   Your turn ended, but this project counts a task as done only once its work
   is committed and pushed to its branch's upstream — and yours is not yet.

   These changes of this task are not committed (as `git status --short` shows them):
     ?? pkg/redact/registry.go
      M pkg/audit/audit.go
   ...
   ```

5. **If the turn still ends that way**, the attempt is aborted with
   `uncommitted_work` and the task goes back to `pending` instead of `done`.

The check never reverts, stashes or commits the agent's work. It only reads the
repository, and git runs with optional locks off, so even reading the status
doesn't rewrite the index while the agent works. The work stays where the agent
left it.

### What is never the task's

- **What was already there.** A path that was dirty when the attempt started
  and hasn't changed since (your own edits, `cloop init`'s addition to
  `.gitignore`, a tree a crashed run left behind) is not blamed on the task,
  and the agent is told to leave it alone. If the agent changes such a path
  further, or stages it, it becomes the task's.
- **Commits that were already local.** With *pushed*, only commits the attempt
  made count. Commits that were on `HEAD` but unpushed when the attempt started
  are not its job to publish.
- **cloop's own directory.** `.cloop/` is never checked, whether or not the
  repository ignores it. That includes its state, artifacts, the
  [parallel task worktrees](../reference/commands.md) and the
  [feature worktrees](features.md) under `.cloop/features/`.

### The next attempt is held to the same work

An aborted attempt leaves its changes in the tree, so the next attempt would
find them there at the start and count them as someone else's. To prevent
that, cloop records the paths an attempt was blamed for, and the `HEAD` it
started at, in `.cloop/artifacts/<task-id>_uncommitted.json`, and holds the
next attempt at the same task to them. The record is removed once the task's
work is committed, and ignored after seven days.

### Bounded

This hand-back shares its limit with the
[unfinished-turn hand-back](../getting-started/concepts.md#the-signal-protocol):
at most two per attempt in total. The abort counts towards the run's limit on
consecutive aborts (`--max-failures`, default 3), like every other abort. An
aborted task is retried after a short wait. If the limit is reached on an
`uncommitted_work` abort, the run **pauses** with the reason *work left
uncommitted* instead of looping. The dashboard shows the pause, and the event
journal has a `task_aborted` row per attempt (with the paths, the unpushed
commits and the upstream) and a `session_paused` row. Commit or revert the
work, then start the run again.

## Pushing

With *pushed*:

- **A branch without an upstream is not checked.** This covers a parallel
  task's worktree branch, a feature branch and a detached `HEAD`. The task gets
  a note ("branch … has no upstream: the push was not checked") but does not
  fail. Give the branch an upstream (`git push -u`) if you want it checked.
- **Pushes held by the review gate count as pending.** With the
  [review gate](review-gate.md) on, the agent's pushes are held until the
  reviewer approves, and then cloop sends them. A commit covered by a held push
  counts as pending and does not hand the turn back. If the gate cannot hold
  pushes on this machine, it tells the agent not to push at all, and the push
  is not checked.
- **The check runs before the review.** A task with unfinished work is not
  reviewed, and its held pushes are not sent. The gate's own fix turns are
  checked the same way afterwards.
- **A push that can never succeed**, such as one with a read-only grant or a
  branch-restricted [GitHub grant](secrets.md) that excludes the branch, keeps
  the task from ever being done. Use *committed* for such a project.

## Where the check runs

The check runs where the work is:

| Run | Checked in |
|---|---|
| Sequential | the project's working directory |
| Parallel with `--worktree-parallel` | each task's own worktree under `.cloop/worktrees/` |
| Parallel in one shared tree | **not checked** while tasks run side by side, because their changes can't be told apart and each task would be blamed for the others'. The task is annotated. Use `--worktree-parallel`. |
| A [feature](features.md) | the feature's own worktree, against its own setting |
| An isolating executor | inside the sandbox, by the `cloop run` there. The setting arrives with the project. |

If an attempt in a task worktree ends with work uncommitted, cloop **keeps** the
worktree (locked with `git worktree lock`) instead of removing it, because its
branch holds only what was committed. The next attempt reopens it as it was
left. `cloop worktree prune` and the hub's startup sweep leave locked
worktrees alone.

A project directory that is not a git repository is not checked, and the run
says so for each task.

An older `cloop` inside a sandbox or on an edge device ignores the setting, as
it ignores any field it doesn't know. Upgrade it.

## Recovery

If a run dies while a turn is handed back, stale-task recovery must not adopt
the agent's `TASK_DONE`. The hand-back records the attempt as `pending` (reason
`uncommitted_work`) in the task's verdict sidecar,
`.cloop/artifacts/<id>_verdict.json`, which recovery reads before the agent's
own signal. The abort records it again before it is announced. Recovery puts
such a task back in the queue. With the [review gate](review-gate.md) on, the
gate's pending verdict already stops an unreviewed `TASK_DONE` from being
adopted.

The janitor removes `<id>_uncommitted.json` records once they are a week old,
the age after which they are ignored anyway.
