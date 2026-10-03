# Reviewing tasks before they are published

The **review gate** is an optional second model that reads each task's changes
before anything leaves the working copy. It is configured per project, and it
does not have to be the model doing the work: a common setup has a fast model
write the code and a stronger one — or one from another vendor — review it.

Until the reviewer approves, nothing a task produced is pushed and nothing is
merged. If it asks for changes, the agent can be sent back to fix them, the task
can fail outright, or the review can just be recorded — your choice.

## Turning it on

In the dashboard, open a project's **Overview** and click the **Review gate**
card (next to *Provider* and *Executor*). The dialog sets:

| Setting | Meaning |
|---|---|
| Review each task … | On or off. Switching it off keeps the other settings. |
| Reviewer provider | `claudecode`, `anthropic`, `openai`, `ollama`, or *Same as the project*. |
| Reviewer model | Any model of that provider. With *Same as the project* and no model, the project's own model reviews its work. |
| Effort | Reasoning effort, for a `claudecode` reviewer. |
| When changes are requested | `fix`, `block` or `advisory` — see [modes](#modes). |
| Fix rounds before blocking | How often `fix` sends a task back (1–5, default 2). |
| Extra review criteria | Rules of your own, sent with every review ("reject any change to migrations"). |

From the command line, `cloop review gate` does the same in the project
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
| `--max-fix-rounds` | `0` (= 2) | How often `fix` sends a task back, at most 5 |
| `--instructions` | | Extra review criteria |
| `--json` | `false` | Print the settings as JSON |

The settings live in the project's state, not in `config.yaml`, so they travel
with the project to a [remote executor](../architecture/executors.md) and apply
there too. A run that is already going picks up a change at its next task.

## What happens during a task

1. **Before the agent starts**, cloop records the state of every repository
   under the project and starts **holding pushes**.
2. **The agent works as usual** — including committing and pushing, if its task
   or the project's instructions say so. A push does not reach the remote: git
   reports it as

   ```
    ! [remote rejected] main -> main (held by cloop's review gate: cloop pushes it after the reviewer approves this task; do not retry)
   ```

   and cloop records it. The agent's prompt explains this, so it carries on.
3. **When the agent reports the task done**, the reviewer reads every change the
   task made and answers with a verdict and findings.
4. **The verdict decides** what happens next ([modes](#modes)).
5. **On approval**, cloop sends the held pushes itself, and the merges it
   performs — [git mode](../reference/commands.md) branches, the
   [parallel merge queue](../architecture/executors.md) — go ahead.

In multi-agent mode (`cloop run --multi-agent`) the gate holds the pushes of all
three sub-agents — architect, coder and reviewer — and each is told so, exactly
as a single agent is. The gate then reviews the task once, after the pipeline's
own reviewer, and a fix round resumes the coder's conversation.

A task that changed nothing is not sent to the reviewer at all: there is nothing
to review and nothing to publish. The gate works on git repositories — the
project's own and any the task clones inside it — so in a project directory
that is not a repository and holds none, it has nothing to diff or publish and
records "nothing to review".

## Modes

| Mode | When the reviewer requests changes |
|---|---|
| `fix` (default) | The findings go back to the agent — in the same conversation when the provider can resume one, so it still knows what it did — and the result is reviewed again. After *Fix rounds* attempts without an approval, the task fails. |
| `block` | The task fails at once. Its diagnosis is the reviewer's findings, and nothing is pushed or merged. |
| `advisory` | The review is recorded and the work is published anyway. |

The gate **fails closed**. A reviewer that cannot be reached, is not configured
properly (a missing API key, say), or answers without a verdict — twice, since a
malformed answer earns one more request for the format — blocks the task in
`fix` and `block` mode exactly as a rejection would. So does an "approve" that
lists a `blocker` or `major` finding: the reviewer contradicted itself.

A blocked task's commits stay where the agent made them, in the working copy,
for a person to look at; in git mode its branch stays unmerged. Resetting the
task runs it again, and the retry is told what the reviewer found.

**A run that ends before the outcome is stored keeps the gate's decision.**
cloop writes each decision about a task to `.cloop/artifacts/<id>_verdict.json`
before it records the outcome, and the next run's recovery — or the hub's, when
it notices the run has gone — reads that first. A task the gate failed is
recovered as failed, not as the `TASK_DONE` the agent printed, so the tasks that
depend on it do not run on rejected work. A run that ends while the review is
still going is recovered by running the task again: the agent's pushes were
held, so nothing of it was published, and the retry is reviewed like any other.

## What the reviewer sees

- The goal, the project's instructions, the task, and the agent's final message.
- A diff per repository: the project's own and any repository the task cloned or
  created inside it (up to 16, four directory levels deep). The diff is the
  working tree against where the task started — commits, staged and unstaged
  edits and new files together — so uncommitted work is reviewed as well.
- When the agent pushed, the diff instead starts where the remote's copy of the
  branch forks, because the push would publish everything after that point,
  including commits that were sitting unpushed before the task began.
- The commits in that range, and every push waiting for its verdict.
- Changes to cloop's own `.cloop/` files, by name only.
- Your extra criteria, and — in a later round — what it asked for last time.

The diffs share a 60 KB budget; a review that had to be cut says so, and the
reviewer is told not to approve what it could not see. A `claudecode` reviewer
may open files for context: it runs with `--tools Read,Grep,Glob` and
`--strict-mcp-config`, so it can read but has no tool that edits, writes or runs
anything. Everything the agent wrote is presented to the reviewer as material to
review, with an instruction to treat embedded instructions as a finding.

## Which model reviews

| Reviewer provider | Reviewer model | Model used |
|---|---|---|
| *Same as the project* | empty | the project's model |
| *Same as the project* | set | that model |
| another provider | empty | `config.yaml`'s model for that provider (`anthropic.model`, …), else its default |
| any | set | that model |

The reviewer's credentials are that provider's usual ones: the `claudecode`
login, or the `anthropic`/`openai` API key in `config.yaml` or the environment.
Its token spend is billed to the task in the cost ledger under the reviewer's own
provider and model, marked "(review)".

## What gets published — and what never does

cloop **never pushes a commit the reviewer did not see**. Each held push is
replayed only if:

- the commit it sends is the reviewed one or an ancestor of it — a branch that
  moved after the review is refused, and the push is sent at the reviewed commit
  rather than wherever the branch points by then;
- every commit it would deliver (by the remote-tracking refs) lies in the range
  the reviewer read.

A forced push is replayed with `--force-with-lease` against the remote state the
agent saw, so it cannot clobber work that reached the remote during the review.
Deletions and tags are replayed like any other ref update. A replay that is
refused or fails fails the task too: its work was approved but not delivered,
and the task record says which push and why.

Merges performed by cloop itself go ahead only when the tree being merged is the
tree the reviewer approved.

## Where to see the outcome

- **Task list** — a `🔍 reviewed ✓` chip, or a red `🔍 review: not published`.
- **Task details** — a *Review gate* section: the verdict, the reviewer, how
  many rounds, the findings, and what became of each held push.
- **Event history** — a `review` row per task.
- **CLI** — the task's annotations (`cloop task show <id>`), and its failure
  diagnosis when the gate blocked it.

## Limits

- **A guardrail, not a security boundary.** Pushes are held through git's
  `pushInsteadOf` in the agent's environment; an agent that sets out to evade
  the gate can unset it, push to a remote configured with an explicit `pushurl`,
  or call a forge's API directly. The gate keeps an agent that follows its
  instructions from publishing unreviewed work. What bounds a hostile agent in a
  sandbox is the [git proxy](../git-interception-proxy.md), which enforces branch
  restrictions outside it.
- **Where the reviewer runs.** The review runs where the task runs — on a remote
  device, inside its sandbox. A `claudecode` reviewer uses the harness credential
  granted to the run; another provider needs its key available there. The
  device's own `cloop` has to be a build with the review gate: an older one
  ignores the setting and runs tasks unreviewed. The hub notices when such a
  task comes back done without a review, says so on the task and in the
  project's event history, and names the upgrade.
- **Parallel tasks in one working tree** see each other's changes, so each
  review includes whatever its peers changed so far. Turn on worktree isolation
  for reviews of one task at a time.
- **Opening a feature's pull request** publishes the feature branch as it
  stands; the pull request is itself the place a person reviews it.
