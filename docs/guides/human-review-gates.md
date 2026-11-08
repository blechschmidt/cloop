# Stopping a run for review

A human review gate is an entry in the task list that no agent runs. When a run
reaches it, the run stops. Every task above the gate has finished, and nothing
below it starts until someone approves the gate.

Use one when the next tasks build on a result you want to check first: the data
model before the API goes on top of it, the parser before the code generator,
the migration before anything runs against it. While the run waits you can
look at the work, edit the tasks below the gate, or add tasks above it to fix
or improve what was done. Then approve the gate and the run carries on.

This is different from the [review gate](review-gate.md), where a second model
reads each task's changes before they are pushed. A human review gate stops the
whole run at one point in the list, for a person.

## Adding a gate

In the dashboard, open a project's **Tasks** tab and click **+ Review gate**
above the task list. The gate is added at the end of the queue. Drag it to
where the run should stop, the same way you reorder tasks. Gate rows have a
dashed yellow border and a ⏸ icon.

On the command line, in the project directory:

```bash
cloop task gate add                     # at the end of the queue
cloop task gate add --after 4           # right after task 4
cloop task gate add --before 7 --title "Check the schema" --note "Look at the migration first"
```

`--after` a task that has already run puts the gate at the head of the queue:
the run stops as soon as the tasks running now have finished. `--before` needs
a task that is still queued. Without `--title` the gate is called *Human
review*. The note is shown with the gate, so use it to say what the reviewer
should look at.

## Moving a gate

A gate keeps its place in the queue like any task. Drag it up or down in the
dashboard, or move it one place at a time:

```bash
cloop task move 12 up      # stop one task sooner
cloop task move 12 down    # let one more task run first
```

Only pending entries have a place in the queue; finished and running tasks
don't. Pinned tasks always run first, so a gate can't be moved past a pinned
task. Unpin the task first.

## When a run reaches a gate

The run stops once every task above the gate has finished, whether it was done,
skipped or failed. In parallel mode it waits for all of them. A task above the
gate that depends on a task below it can't start either, so the run stops then
too.

You then see:

- the project paused with *waiting for human review at gate #12* and the gate's
  title, on the Projects page, the Overview and the Tasks tab;
- the gate's row saying *waiting for review*, with an **Approve & continue**
  button;
- a row in the project's event history, a desktop notification if the run was
  started with `--notify`, and a message to the project's Slack or Discord
  webhook if one is set.

A gate at the end of the list stops the run before the plan counts as complete.
With auto-evolve on, no new tasks are planned until you approve it.

Pressing **Start run** while the run waits at a gate with nothing left above it
is refused with a message naming the gate, so no executor is started just to
stop again.

## Reviewing and carrying on

When the work above the gate is what you wanted, approve the gate:

- In the dashboard, click **Approve & continue**. The gate is approved and the
  run starts again. On a gate the run hasn't reached yet the button says
  **Approve**, and runs then go straight past it.
- On the command line, run `cloop task gate approve 12`, then `cloop run`.

When something needs fixing first, change the plan before approving:

1. Edit the tasks below the gate, or add new tasks and drag them above it
   (`cloop task add`, then `cloop task move`).
2. Press **Start run** (or `cloop run`) without approving. The run carries out
   the tasks you put above the gate and stops at the gate again.
3. Check the result. Repeat, or approve the gate.

**Reopen** on an approved gate's row (`cloop task gate reopen 12`) closes it
again, so runs stop there once more. `cloop task skip 12` bypasses a gate
without approving it. `cloop task done` and `cloop task reset` work on a gate
too: done approves it, reset closes it again.

## Who can approve

Anyone who may edit the project's tasks may add, move, approve or remove a
gate. Each approval is recorded in the project's audit trail as
[`task.gate_approve`](../reference/audit-events.md#task), with who approved
it, whether a run was waiting, and whether it came from the dashboard or the
command line.

An agent can't approve a gate as part of its task. The orchestrator never hands
a gate to an agent, and `cloop task gate approve` refuses to run inside a
task's run, where the environment names the task. That check is a guard against
an agent approving a gate by mistake. On a local executor an agent can write
the project's database, so it is not a security boundary there.

A run on a remote executor can't open a gate either. When the run's results come
back, the hub ignores any result that says a gate was passed unless the hub's
own copy of that gate was approved.

## Remote executors

Gates travel with the project to a remote executor, and the run there stops at
them like a local one. A device agent older than protocol 27 doesn't know about
gates and would run one as an ordinary task, so the hub refuses to send it a
plan that holds a pending gate and says which upgrade it needs. Approve or
remove the gate, or [upgrade the agent](../architecture/executors.md).

A container sandbox or Kubernetes Pod runs the cloop in its image. Use an image
from the same release as the hub, or newer, for projects with gates.
