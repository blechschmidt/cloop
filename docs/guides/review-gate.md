# Reviewing tasks before they are published

The **review gate** is an optional second model that reads each task's changes
before anything leaves the working copy. You configure it per project, and it
doesn't have to be the model doing the work. A common setup has a fast model
write the code and a stronger one, or one from another vendor, review it.

Until the reviewer approves, nothing a task produced is pushed or merged. If
the reviewer asks for changes, you choose what happens: the agent is sent back
to fix them, the task fails, or the review is only recorded.

## Turning it on

In the dashboard, open a project's **Overview** and click the **Review gate**
card (next to *Provider* and *Executor*). The dialog sets:

| Setting | Meaning |
|---|---|
| Review each task … | On or off. Switching it off keeps the other settings. |
| Reviewer provider | `claudecode`, `anthropic`, `openai`, `ollama`, or *Same as the project*. |
| Reviewer model | Any model of that provider. With *Same as the project* and no model, the project's own model reviews its work. |
| Effort | Reasoning effort, for a `claudecode` reviewer. |
| When changes are requested | `fix`, `block` or `advisory`. See [modes](#modes). |
| Fix rounds before blocking | How many times `fix` sends a task back (1–5, default 2). |
| Extra review criteria | Your own rules, sent with every review ("reject any change to migrations"). |

On the command line, `cloop review gate` does the same in the project
directory:

```bash
cloop review gate                                   # show the settings
cloop review gate --enable --provider anthropic --model claude-opus-5-5
cloop review gate --enable --model claude-opus-5-5 --effort high   # the project's own provider
cloop review gate --mode block --instructions "Reject changes to migrations/."
cloop review gate --disable
```

| Flag | Default | Description |
|------|---------|-------------|
| `--enable` / `--disable` | | Turn the gate on or off |
| `--provider` | the project's | Reviewer provider |
| `--model` | see [below](#which-model-reviews) | Reviewer model |
| `--effort` | provider default | Reviewer reasoning effort (`claudecode` only) |
| `--mode` | `fix` | `fix`, `block` or `advisory` |
| `--max-fix-rounds` | `0` (= 2) | How many times `fix` sends a task back, at most 5 |
| `--instructions` | | Extra review criteria |
| `--json` | `false` | Print the settings as JSON |

The settings are stored in the project's state, not in `config.yaml`, so they
travel with the project to a [remote executor](../architecture/executors.md)
and apply there too. A run that is already going picks up a change at its next
task.

## What happens during a task

1. **Before the agent starts**, cloop records the state of every repository
   under the project and starts **holding pushes**.
2. **The agent works as usual**, including committing and pushing if its task
   or the project's instructions say so. A push doesn't reach the remote:
   git reports it as

   ```
    ! [remote rejected] main -> main (held by cloop's review gate: cloop pushes it after the reviewer approves this task; do not retry)
   ```

   and cloop records it. The agent's prompt explains this, so the agent carries
   on.
3. **When the agent reports the task done**, the reviewer reads every change the
   task made and answers with a verdict and findings.
4. **The verdict decides** what happens next ([modes](#modes)).
5. **On approval**, cloop sends the held pushes itself, and the merges it
   performs ([git mode](../reference/commands.md) branches and the
   [parallel merge queue](../architecture/executors.md)) go ahead.

In multi-agent mode (`cloop run --multi-agent`), the gate holds the pushes of
all three sub-agents (architect, coder and reviewer), and each is told so, as a
single agent is. The gate then reviews the task once, after the pipeline's own
reviewer, and a fix round resumes the coder's conversation.

A task that changed nothing is not sent to the reviewer, because there is
nothing to review or publish. The gate works on git repositories: the project's
own and any the task clones inside it. In a project directory that is not a
repository and contains none, there is nothing to diff or publish, and the gate
records "nothing to review".

## Modes

| Mode | When the reviewer requests changes |
|---|---|
| `fix` (default) | The findings go back to the agent (in the same conversation when the provider can resume one, so it still knows what it did), and the result is reviewed again. After *Fix rounds* attempts without an approval, the task fails. |
| `block` | The task fails at once. Its diagnosis is the reviewer's findings, and nothing is pushed or merged. |
| `advisory` | The review is recorded and the work is published anyway. |

The gate fails closed. In `fix` and `block` mode, the task is blocked as if the
reviewer had rejected it when the reviewer can't be reached, is misconfigured
(a missing API key, for example), or answers without a verdict twice (after a
malformed answer, cloop asks once more for the right format). An "approve" that
lists a `blocker` or `major` finding is treated the same way, because the
reviewer contradicted itself.

A blocked task's commits stay in the working copy where the agent made them, for
a person to look at. In git mode its branch stays unmerged. Resetting the task
runs it again, and the retry is told what the reviewer found.

If a run ends before the outcome is stored, the gate's decision is kept. cloop
writes each decision about a task to `.cloop/artifacts/<id>_verdict.json`
before it records the outcome, and recovery reads that file first, whether it
is the next run's recovery or the hub's after it notices the run has gone. A
task the gate failed is recovered as failed, not as the `TASK_DONE` the agent
printed, so tasks that depend on it don't run on rejected work. If a run ends
while the review is still going, recovery runs the task again. The agent's
pushes were held, so none of its work was published, and the retry is reviewed
like any other task.

## What the reviewer sees

- The goal, the project's instructions, the task, and the agent's final message.
- A diff per repository: the project's own and any repository the task cloned or
  created inside it (up to 16, four directory levels deep). The diff compares
  the working tree with where the task started, covering commits, staged and
  unstaged edits and new files, so uncommitted work is reviewed too.
- If the agent pushed, the diff starts instead where the remote's copy of the
  branch forks, because the push would publish everything after that point,
  including commits that were already unpushed before the task began.
- The commits in that range, and every push waiting for the verdict.
- Changes to cloop's own `.cloop/` files, by name only.
- Your extra criteria and, in a later round, what the reviewer asked for last
  time.

The diffs share a 60 KB budget. A review that had to be cut says so, and the
reviewer is told not to approve what it could not see. A `claudecode` reviewer
can open files for context. It runs with `--tools Read,Grep,Glob` and
`--strict-mcp-config`, so it can read but has no tool that edits, writes or
runs anything. Everything the agent wrote is given to the reviewer as material
to review, with an instruction to treat any instructions embedded in it as a
finding.

## Which model reviews

| Reviewer provider | Reviewer model | Model used |
|---|---|---|
| *Same as the project* | empty | the project's model |
| *Same as the project* | set | that model |
| another provider | empty | `config.yaml`'s model for that provider (`anthropic.model`, …), else its default |
| any | set | that model |

The reviewer uses that provider's usual credentials: the `claudecode` login, or
the `anthropic`/`openai` API key in `config.yaml` or the environment. Its token
spend is billed to the task in the cost ledger under the reviewer's own provider
and model, marked "(review)".

## What gets published — and what never does

cloop never pushes a commit the reviewer did not see. It replays a held push
only if:

- the commit it sends is the reviewed one or an ancestor of it. If the branch
  moved after the review, the push is refused, and an accepted push is sent at
  the reviewed commit, whatever the branch points to by then;
- every commit it would deliver (according to the remote-tracking refs) lies in
  the range the reviewer read.

A forced push is replayed with `--force-with-lease` against the remote state the
agent saw, so it can't overwrite work that reached the remote during the review.
Deletions and tags are replayed like any other ref update. If a replay is
refused or fails, the task fails too, because its work was approved but not
delivered. The task record says which push and why.

Merges that cloop performs itself go ahead only when the tree being merged is
the tree the reviewer approved.

## Where to see the outcome

- **Task list**: a `🔍 reviewed ✓` chip, or a red `🔍 review: not published`.
- **Task details**: a *Review gate* section with the verdict, the reviewer, the
  number of rounds, the findings, and what happened to each held push.
- **Event history**: a `review` row per task.
- **CLI**: the task's annotations (`cloop task show <id>`), and its failure
  diagnosis when the gate blocked it.

## Limits

- **A guardrail, not a security boundary.** Pushes are held through git's
  `pushInsteadOf` in the agent's environment. An agent that tries to get around
  the gate can unset it, push to a remote configured with an explicit `pushurl`,
  or call a forge's API directly. The gate stops an agent that follows its
  instructions from publishing unreviewed work. What limits a hostile agent in a
  sandbox is the [git proxy](../git-interception-proxy.md), which enforces
  branch restrictions outside the sandbox.
- **Where the reviewer runs.** The review runs where the task runs, so for a
  remote device it runs inside the task's sandbox. A `claudecode` reviewer uses
  the harness credential granted to the run. Any other provider needs its key
  available there. The device's own `cloop` must be a build that includes the
  review gate; an older one ignores the setting and runs tasks unreviewed. When
  such a task comes back done without a review, the hub says so on the task and
  in the project's event history, and names the upgrade.
- **Parallel tasks in one working tree** see each other's changes, so each
  review includes whatever the other tasks have changed so far. Turn on
  worktree isolation to review one task at a time.
- **Opening a feature's pull request** publishes the feature branch as it is.
  The pull request is where a person reviews it.
