# Requirements

A task says what to do next. A **requirement** says what the project must keep
doing, however many tasks later: "a malformed config makes every command exit
non-zero", "every API route declares a permission", "rolling back restores the
previous version byte for byte". Requirements belong to a project and are
stored in its database beside the plan. You check them to find out whether
work that was done still holds.

A requirement may have **tests**: shell commands, run in the project's root,
that pass when they exit 0. Checking a tested requirement runs them. A
requirement with no tests can be **assessed by the model**, which reads the
code and says whether it holds, or given a **verdict by hand**.

A requirement is a **draft**, **approved** or **deprecated**. A check covers
the approved ones unless told otherwise, and nothing checks a draft until a
person approves it. The model can **draft** requirements from the project's
goal or a specification you paste, for you to review and approve (see
[Drafting requirements with the model](#drafting-requirements-with-the-model)),
and **lint** says which requirements are vague, compound, repeated,
contradictory or untested. Requirements can also be kept **as code**, in
`.cloop/requirements.yaml` beside the code they govern, where they are reviewed
in pull requests and checked by a CI job without a hub (see
[Requirements as code](#requirements-as-code)).

The planners use them too. **Plan from requirements** has the model plan the
tasks that close the open gaps, must requirements first, each task linked to
what it closes. Auto-evolve, the suggestions panel, the plan assistant and
Split also take the requirements into account (see
[Planning from the requirements](#planning-from-the-requirements)).

## Adding requirements

In the dashboard, open a project's **Requirements** tab and press
**+ Add requirement**. Enter a title, the details (what the requirement means,
which is also what the model reads when there is no test to run), the tests
(one command per line), a priority (`must`, `should`, `could`), a status and
tags.

From a terminal, in the project's directory:

```bash
cloop requirements add "Config errors exit non-zero" \
    -d "A malformed config.yaml makes every command exit 2 and name the line." \
    --test "go test ./pkg/config -run TestMalformed" --priority must --tag cli
cloop requirements add "Rollbacks never lose a config" --priority should
cloop requirements list
```

`cloop requirements edit <id>` changes one (`--test` replaces its tests,
`--clear-tests` removes them, `--status` approves or deprecates it),
`cloop requirements show <id>` prints it with its latest check, and
`cloop requirements remove <id>` deletes it along with the history of its
checks. Requirements are numbered `R-1`, `R-2`, … and a number is never reused
after its requirement is deleted, so a verdict, an audit row or a task that
names `R-7` always refers to the same requirement. A spec file follows the same
rule.

### Statuses

| Status | Means | Checked |
| --- | --- | --- |
| **draft** | proposed, not yet agreed | never, until a person approves it |
| **approved** | the project must keep it | by every check, unless told otherwise |
| **deprecated** | no longer required; kept for its history | only when named |

A requirement added without a status is approved, and so is every requirement
written before statuses existed, so nothing that was checked stops being
checked. **Check all** and `cloop requirements check` with no ids check the
approved requirements. Naming a requirement (**Check** on its card,
`cloop requirements check 4`) also checks a deprecated one, and
`--status deprecated` or `--all` widens a check from the terminal.

Nothing checks a **draft**: not **Check all** or `--all`, not naming it
(`cloop requirements check 4` and the dashboard refuse it), and not the
[requirements gate](#requirement-gated-completion). Nobody can record a verdict
for it either. Its tests may be a model's proposal that nobody has read yet,
and nothing runs them until a person has. Approving it lets them run. You
approve a draft with **Approve** on its card or in the Draft dialog, with
`cloop requirements approve 4`, by saving it in the form with the status
*approved*, or by importing a spec file that approves it. Whoever approves it
is recorded as its **approver** (shown on its card, and as `approved_by` and
`approved_at` in the API), and the approval is a `requirement.approve` row in
the project's audit trail. Approving or deprecating a requirement does not make
its verdicts stale, because it still says the same thing.

### Writing tests

A test is a command for `/bin/sh -c`, run in the project's root with the
environment of the workload that checks it, plus `CLOOP_REQUIREMENT_ID` and
`CLOOP_REQUIREMENT` (`R-<id>`). Point it at the narrowest thing that proves the
requirement (a single test function, a script in the repository), not the whole
suite, because a check runs every test of every requirement, one after another.

- **Timeout.** Each test may run for 10 minutes unless it says otherwise (at
  most 2 hours). A test that runs out of time is an *error*, not a failure,
  because the check could not reach a result.
- **Nothing is left running.** A test runs in a process group of its own, and
  the whole group is killed when it ends, however it ends. A test that starts a
  server in the background and exits takes the server with it.
- **Output.** The last 16 KiB of what a test printed, stdout and stderr
  together, is kept with its result, since the end usually says why a test
  failed. It is scrubbed first of the credentials leased to the workload,
  anything shaped like a credential, and the hub's root key, which never
  reaches a test's environment at all.
- **Size.** A requirement and its tests must fit in 64 KiB as the hub sends
  them; put a long command in a script in the repository and call that.

## Drafting requirements with the model

The model can turn free text (the project's goal, a specification, user
stories, meeting notes) into atomic, testable requirements, each a sentence in
EARS form:

| Pattern | Form |
| --- | --- |
| event | When *trigger*, the system shall *response*. |
| state | While *state*, the system shall *response*. |
| unwanted behaviour | If *condition*, then the system shall *response*. |
| optional feature | Where *feature is included*, the system shall *response*. |
| always | The system shall *response*. |

Each draft also gets acceptance criteria under its details, a suggested
priority, tags and, where the repository makes one obvious (an existing test, a
make target, a script), a test command. Everything the model drafts is stored
as a **draft**, which counts for nothing until you approve it.

In the dashboard, press **Draft requirements** in the Requirements tab. Choose
to draft from **a specification** (paste it, or load a Markdown or text file
from your computer into the box) or from **the project's goal**, set the
maximum number of drafts, and press **Draft**. The dialog lists every draft
awaiting approval with its acceptance criteria, its proposed test and what
[lint](#linting-requirements) says about it, and the proposals the model made
that were refused, with the reasons. For each draft, choose **Approve**,
**Edit first** (the requirement opens in the tab's form, where saving it as
*approved* approves it) or **Discard**. **Approve all** approves every draft
the dialog shows. When a tab has drafts, it says so above the list, with
**Review drafts**.

From a terminal, in the project's directory:

```bash
cloop requirements draft --from-goal          # the project's goal
cloop requirements draft --from-file spec.md  # a specification
cat notes.md | cloop requirements draft       # stdin
cloop requirements draft --from-file spec.md --dry-run --max 5   # show them, store none
cloop requirements approve 12 13              # or --all-drafts
```

### Where the model runs

A draft from the dashboard is a model call like the Split preview. The hub
dispatches `cloop requirements draft --json --dry-run` to the project's
executor (its sandbox, its device) with *your* Claude account, or your Copilot
sign-in for a Copilot project, never the hub's, and never on the hub's own
host. A sandbox with no credential of yours refuses it, with the dialog that
grants one. The hub sends the text, the project's goal and the titles of its
existing requirements (so that the model does not restate one) as arguments.
An agent that can read the repository (Claude Code, Copilot) may read it to
find out how its tests run, and is told not to change anything. An executor
whose `cloop` is older than the hub reports that.

### What the model's answer must be

Its answer is untrusted text, read in two steps:

1. **Strictly.** It must be one JSON object in the draft format and nothing
   else, with at most one Markdown code fence around it. If there is prose
   before or after it, a second object, or a field the format does not have,
   nothing is drafted, so an example the model quotes, or an object in a pasted
   specification, is never taken for the answer. The text drafted from is
   fenced in the prompt by markers derived from its own hash, and the model is
   told it is data, not instructions.
2. **Each proposal against a requirement's bounds**: the same ones that apply
   to a requirement you type (see [Limits](#limits)), plus at most 10
   acceptance criteria of 500 characters each. A proposal that does not fit is
   **refused** with the reason, never cut to fit, and so is one that repeats an
   existing requirement or an earlier proposal word for word. An invalid tag is
   dropped.

A proposal can only ever be a draft. One that asks for any other status is
refused, not demoted, because a model that tries to approve its own proposal,
or a specification that tells it to, needs a person's attention. The hub checks
what the executor's `cloop` sends back against its own copy of these rules,
since that `cloop` may be anything, and the dashboard escapes everything in it.
Each draft is a `requirement.create` row naming what it was drafted from
(`drafted`), and the draft as a whole is one `requirement.draft` row: who
asked, from what (`goal`, `text`, `file` or `stdin`), the text's SHA-256 and
length (not its content), the drafts stored, and how many proposals were
refused.

### Linting requirements

`cloop requirements lint`, and the lint pass in the Draft dialog, read the
requirements as written:

| Finding | Severity | Means |
| --- | --- | --- |
| `ambiguous` | warning | wording a check cannot measure ("fast", "user-friendly", "should handle", "etc.", "as appropriate"), each with a suggested replacement |
| `compound` | warning | more than one behaviour: a second "shall", a semicolon, a second sentence, "and" before a second verb |
| `duplicate` | error | a requirement that repeats another |
| `contradiction` | error | two requirements that cannot both hold |
| `untested_must` | error | an approved `must` requirement with no test: only the model or a person can say it holds, and the gate's `linked+must` mode passes it by |

By rule, lint finds near-duplicates and contradictions by their wording: two
statements that are nearly the same, or the same with one negated. **Check with
the model** in the dialog, or `--ai`, also asks the model, on the project's
executor with your account, whether each draft repeats an agreed requirement in
other words (the same semantic dedup that stops auto-evolve adding a task the
plan already has), and which pairs contradict each other. Its answers are read
as strictly as a draft, and for each finding the hub keeps only the
requirements it names and the model's reason.

```bash
cloop requirements lint               # every requirement but the deprecated ones
cloop requirements lint R-12 R-13     # these
cloop requirements lint --ai          # and ask the model
cloop requirements lint --file .cloop/requirements.yaml --strict   # in CI
```

It exits 1 on an error, and with `--strict` on a warning too, so a CI job can
run it as a gate.

## Checking whether they are still fulfilled

Press **Check all** in the Requirements tab to check the approved requirements,
or **Check** on one requirement. The check runs where the project's runs run.
The hub dispatches `cloop requirements check` to the project's executor (its
container sandbox, its device, its Pod) with the project's lease, firewall and
resource limits, in the same way as it dispatches a task. The hub never runs a
requirement's tests on its own host, unless the project's tasks also run there
(`executors.allow_host_process`).

A check runs in the background. The tab shows it while it runs and updates as
each batch of requirements is recorded, and the check keeps running if you close
the tab that started it. **Stop** ends it. One check runs at a time per
project, on whichever hub member was asked; a second is refused, and the error
names the one running. A check whose hub member stopped is recorded as failed,
and one whose member died lapses at its deadline (the sum of its tests'
timeouts, at most six hours).

From a terminal:

```bash
cloop requirements check          # every approved requirement
cloop requirements check 3 R-5    # just these, whatever their status
cloop requirements check --all    # every requirement
cloop requirements history 3      # its recent checks, newest first
```

`cloop requirements check` exits 1 when a requirement is unfulfilled or its
check did not work, so it can gate a CI job, either with the project's database
or, with `--file`, from the spec file alone
([In CI, without a hub](#in-ci-without-a-hub)).

When you run it by hand, it records what it finds in the project, as
`cli:<user>` on the executor `local`.

### Verdicts

| Verdict | Means |
| --- | --- |
| **fulfilled** | every test passed, or the model or a person said it holds |
| **unfulfilled** | a test failed, or the model or a person said it does not hold |
| **unverified** | the model was asked and could not tell |
| **error** | the check did not work: a test timed out or could not start, the executor's `cloop` sent back nothing (an executor running a `cloop` older than the hub says so) |

A requirement with no tests is **skipped** by a check that does not ask the
model, and its last verdict stands. Each recorded check carries the commit the
tree was at, whether it had uncommitted changes, where it ran and who asked.

### Requirements nothing tests

Tick **Ask the model about untested ones** before **Check all**, press **Ask
the model** on the requirement, or run `cloop requirements check --ai`. The
model is given the requirement's title and details and asked whether the code
in the project fulfils it. It answers with a verdict, a short rationale and the
places in the code its answer is based on. A provider that is an agent harness
(Claude Code, Copilot) reads the tree itself, and any other provider is shown
the files most related to the requirement. On a hub with single sign-on the
model runs on the account of whoever asked, and a sandbox with no Claude
credential for them is refused before anything starts, with the dialog that
grants one.

Or record what you found yourself: open the requirement's **Details** and press
**Mark fulfilled** or **Mark unfulfilled** with a note, or

```bash
cloop requirements verdict 4 fulfilled --note "rolled back staging twice"
```

### When a verdict is stale

A verdict is about the requirement as it read when it was checked. The tab
marks it **stale**

- when the requirement has been **changed** since (its title, details or
  tests), because the verdict is about something it no longer says;
- when **tasks have been done** since the check, because the code may have
  changed. Check again.

## Turning a failure into work

A requirement's **Details** offer **Add a task to restore it**, which adds a
pending task quoting what failed (the failing tests and the end of their
output) and the commands that will show it is fixed. A requirement with no
tests also offers **Add a task to test it**: the agent writes a test that
passes when, and only when, the requirement holds, and names the command that
runs it, which you then add to the requirement. Either task is placed by the
requirement's priority (a `must` goes ahead of the plan's usual work), and
either task [implements the requirement](#tasks-that-implement-a-requirement),
so its run is held to it. A deprecated requirement offers neither.

## Planning from the requirements

The Requirements tab shows, on each approved requirement's card, where it
stands against the plan. Its **gaps** say what is open (it fails, it is stale,
it has no test, no task implements it, nothing has checked it), and its
**action** says what closes it:

| Action | When | Closed by |
| --- | --- | --- |
| **fix** | its latest check of its current definition found it unfulfilled, or could not run its tests | a task that restores it |
| **implement** | nothing shows it holds: never checked, or no test and no verdict | a task that implements it, with a test if it has none |
| **verify** | it was found to hold, but has changed since | a task that verifies it and restores it if needed |
| **test** | it holds by the model's or a person's word and lacks only a test | a task that only adds its test |
| covered | an open task implements it | nothing more |
| check | a task implementing it finished since its verdict, or tasks finished since it held | a check, not a task |
| needs its test | a task implementing it finished and it still has no test | a person attaching the test that task wrote |
| stuck | a task meant to close it failed or was skipped, or is done while it still fails | a person |

The first four are a planner's **targets**. A task cannot close the others,
which is also why auto-evolve cannot loop on a requirement: once a task linked
to a target finishes, fails or is skipped, no planner plans for that target
again until the requirement changes, a check finds it holding, or a person
resets the task. A check that finds it failing again (the requirements gate
checks every must requirement at every task) confirms a failed attempt instead
of undoing it, and a task marked done by hand, with no completion time, counts
as the latest attempt. A requirement whose tests pass needs no task, linked or
not. Drafts and deprecated requirements have no standing and are never planned
for.

### Plan from requirements

**Plan from requirements**, in the Requirements tab, has the model plan the
tasks that close the open gaps (the button shows how many there are). The model
runs on the project's executor with your account, like every dashboard model
call. The plan arrives as numbered steps in the Tasks tab's **AI Feature
Suggestions** panel, which the button opens. Add them one at a time or with
**Add all**, as with any plan. From a terminal:

```bash
cloop requirements plan              # review the plan task by task
cloop requirements plan --dry-run    # show it, add nothing
cloop requirements plan --yes        # add every task
cloop requirements plan --count 5    # at most five tasks
```

Whatever the model proposes is checked against the requirements before you see
it:

- A task links only requirements with an open gap. A link to a draft, a
  deprecated requirement, one that holds, or an id that names nothing is
  dropped.
- A task's **kind** follows from what it links. In a plan from the
  requirements, a task that links only requirements that lack nothing but a
  test is a **test only** task. It goes to the testing role, which is told to
  change nothing else and to end with the command that runs its test, and a
  person then adds that command to the requirement. (A brainstormed idea or a
  planned request that links such a requirement is not treated as one.)
- A task that repeats what an open task implements is left out, and the plan
  says so.
- A must gap the model left open gets a task of its own, from a template.
- The tasks run by the priority of what they close (must at priority 1, ahead
  of the plan's usual work; should at 2; could at 4), each still after the
  tasks it depends on, which run as early as the tasks waiting for them.

Each card says what it closes, with an **R-n** chip per requirement. The panel
shows a warning while an approved must requirement with an open gap is closed
by none of the remaining cards and by no task added from them, so skipping the
only card that closes one triggers the warning. A task added from the plan
[implements](#tasks-that-implement-a-requirement) what its card closed, and its
agent is held to it.

### Auto-evolve and the suggestions panel

An [auto-evolve](../getting-started/concepts.md#auto-evolve) round and the
panel's **Generate** are shown the same summary (every approved requirement
with its gaps, the open ones first) and asked to link what each proposal
closes. When a **must** gap is open, they close it before adding anything new:

- Proposals that close gaps come first, by their requirements' priority, and
  every proposal that closes none runs after all of them.
- A must gap that no proposal closes gets a task from a template (up to five
  per round), even when the model proposed nothing at all.
- Every task a round adds links the approved requirements it addresses: those
  the model named, or those its title names as `R-n`. Anything else is dropped,
  and a project without approved requirements gets no links at all.
- The semantic deduplication also drops a proposal that links only
  requirements an open task already implements, and the model judging the rest
  is shown which requirements each task implements and whether the task is
  open.

A plan for a request you typed keeps the steps and order you asked for, and its
tasks link the requirements they make hold. On a device, the run has no copy of
the hub's checks, so its seed carries what the hub knows about every approved
requirement, and the device's own requirements gate checks are applied on top.
The links of the tasks it adds come back with its result, and are kept where
the hub still has the requirement as approved. A device whose cloop predates
the requirement status is asked again without it, and its answer is still
checked against the requirements on the hub.

### The plan assistant and Split

The plan assistant is shown the same summary. An answer that proposes tasks
ends with a list of them that the dashboard reads. Under the answer, each
proposed task is shown with the requirements it covers, and a warning names the
approved must requirements with an open gap that neither the proposal nor an
open task covers.

**Split**, for a task that implements requirements, asks the model to cover
every approved requirement the task implements. Each proposed sub-task names
the requirements it makes hold, and applying the split links them. The dialog
shows a warning while an approved must requirement of the task is covered by no
selected sub-task, because once the task is split it is skipped, and nothing
open would implement the requirement.

## Tasks that implement a requirement

A task can be linked to the requirements it implements. When the task runs, its
agent is given each one (title, details and test commands) as the task's
**acceptance contract**. The task is done only when those tests pass, run from
the project's root, and the tests must not be weakened to get there: not
edited, skipped, disabled or loosened, and the requirement not narrowed. An
agent that cannot make a test pass, or thinks the test is wrong, is told to say
so and end the task as failed. A requirement with no tests is part of the
contract through its details. The requirements are read when the task starts,
so the task is held to any edit made while it was waiting. A linked **draft**
is named but left out of the contract, without its details and tests, until a
person approves it.

To link a task, tick the requirements in its **Edit** dialog, which lists the
project's approved requirements (and any the task already implements). From a
terminal:

```bash
cloop task add "Make config errors exit non-zero" --no-ai --requirement R-3
cloop task edit 12 --requirement R-3,R-7    # replaces the task's list
cloop task edit 12 --requirement none       # clears it
cloop task show 12                          # "Implements: R-3, R-7"
cloop requirements show R-3                 # lists the tasks that implement it
```

Or use the API: `POST /api/task/add`, `POST /api/tasks`, `POST /api/task/edit`
and `PUT`/`PATCH /api/tasks/{id}` take `requirements`, a list of ids (`3` or
`"R-3"`). On an edit it replaces the task's list, `[]` clears it, and leaving
it out leaves the list unchanged.

A task's card shows a chip for each requirement it implements (**R-3**) that
opens the requirement, and a requirement's **Details** list the tasks that
implement it, each of which opens the task.

Requirement ids belong to the project, so a link always points to a requirement
of the task's own project. An id the project has no requirement for (mistyped,
deleted, or one that only another project has) is refused with a 400 (the CLI
exits non-zero), and so is a new link to a deprecated requirement. A link made
before its requirement was deprecated stays until it is removed, and the
contract names the requirement but leaves it out. Deleting a requirement (from
the dashboard, with `cloop requirements remove`, or by importing a spec file
that no longer has it) removes it from every task that implements it, in the
same transaction. The `requirement.delete` (or `requirement.import`) audit row
names the tasks (`unlinked_tasks`), and each task gets its `task.upsert` row
under the same actor.

A run on an executor that does not share the hub's database (a device, a Pod)
receives, along with the project, the requirements that its plan's unfinished
tasks implement, so its agent is given the same contract. A plan file
(`cloop plan export`) carries no links, because their ids would name other
requirements, or none, in the project that imports it.

## Requirement-gated completion

The contract tells the agent which tests must pass. The **requirements gate**
checks that they do, instead of trusting the agent's `TASK_DONE`. It is off by
default and set per project, to one of three modes:

| Mode | What a task's `TASK_DONE` is checked against |
| --- | --- |
| `off` | Nothing: the agent's word stands, as before. |
| `linked` | The requirements the task implements. |
| `linked+must` | Those, and every approved `must` requirement that has tests: a task may not leave one of them failing. |

```bash
cloop requirements gate                       # show the setting
cloop requirements gate linked
cloop requirements gate linked+must --assess  # and ask the model about untested ones
cloop requirements gate off
cloop run --requirements-gate=linked          # set it, then run
```

In the dashboard it is the **Requirements** badge in the project's Active
Options: each press moves it from off to linked to linked+must and back to off.
The **Assess Untested** badge beside it turns the model's assessment on and
off. You can also declare it in `.cloop/config.yaml`:

```yaml
requirements:
  gate: linked+must   # off | linked | linked+must
  assess: false       # ask the model about linked requirements without tests
```

`cloop run` applies a declared gate to the project before it starts, so for a
project that declares one, the file stays the source of truth. The dashboard
control and `cloop requirements gate` rewrite the declaration when they change
a project that has one, so the two never disagree. A project whose
`config.yaml` declares nothing keeps whatever was set last. A mode the build
does not know is not read as `off`: it counts as declaring nothing, the
project's own setting stands, and every command that loads the file warns
about it. `cloop config set` and `cloop config validate` refuse an unknown
mode.

Like "done means committed", the setting belongs to the project. It travels
with the project to an isolating executor, and a run that is already going
picks it up at its next task.

### What happens when the agent reports done

When an attempt's turn ends in a way the orchestrator would accept as done
(`TASK_DONE`, or an unsignalled finish it would promote), the gate dispatches
`cloop requirements check --json --no-record --spec=<the requirements>` where
the run runs: on the project's executor, in the directory the agent worked in
(the task's worktree, in worktree-parallel mode), never on the hub's host. The
spec carries the requirements as the project defines them, and the report is
read back under the same rules the hub applies to a dashboard check. Commands,
test names and fingerprints come from the project, and a tested requirement's
verdict is recomputed from its tests' outcomes, whatever the report claims.

The check runs after "done means committed", so it tests committed work, and
before the review gate, which must not publish work whose requirements fail.
When the review gate's fix turns change the work, the requirements are checked
again before anything is pushed or merged, and a failure then withholds the
held pushes, as a blocked review does.

What keeps a task from being done:

- a tested requirement whose tests fail, time out or cannot run, including a
  check the executor could not run at all;
- with `--assess`, a linked requirement without tests that the model finds
  unfulfilled.

A linked requirement without tests never blocks. It is reported as
**unverified**, and nothing is dispatched for it unless the project asked for
the model's assessment. A must requirement without tests is not checked in
`linked+must` mode, because only the model could tell whether it regressed, at
one model call per requirement per task. The check says how many were left
out. A deprecated linked requirement is not checked, and neither is a linked
draft: nothing checks a draft until a person approves it, and the check's note
names the drafts it left out.

### Back to pending, then failed

A task whose requirements do not pass is not done. It goes back to pending,
and its next attempt is told what failed, ahead of its instructions:

```text
## REQUIREMENTS NOT MET ON THE LAST ATTEMPT
The last attempt at this task reported TASK_DONE, but this project accepts a task as done only
once its requirements pass, and the checks below did not. They ran in the task's working tree at
commit 1c9d0e4f2a7b.

R-3 Config errors exit non-zero — unfulfilled
  test "go test ./pkg/config -run TestMalformed" failed (exit 1)
  $ go test ./pkg/config -run TestMalformed
  exited 1; its output:
    | --- FAIL: TestMalformed (0.00s)
    |     config_test.go:12: exit code 0, want 2
```

The output is the end of what each failing test printed (at most 4 KiB per
test, 24 KiB in total), scrubbed of credentials and quoted as data. The gate
sends a task back at most `--max-verify-retries` times in a row (default 2), the
same limit as AI verification. The attempt after that fails the task with reason
**`requirements_unmet`**, with the failing checks as its diagnosis. Resetting
the failed task gives it the full count again. In worktree-parallel mode, a
task the gate sends back keeps its worktree, so the next attempt fixes that
work instead of starting over.

Every outcome is stored before anything announces it, and the decision is the
task's verdict for stale-task recovery. While a check runs, the verdict says the
requirements are being checked, so if a run dies mid-check, its task runs again
instead of being accepted as done on the agent's word. A re-queue or failure
that was already decided is applied as the gate decided it. A run stopped while
a check runs returns the task to pending as interrupted.

### Where the verdict is recorded

Every gate check is recorded with the project's requirement checks, tied to the
task and the commit it ran at, under a check run whose source is `gate`, and
audited as `requirement.check`. The Requirements tab shows them like any other
check, naming the task ("for task #12"), and updates as they arrive. The task
keeps the gate's record of its latest check: its card shows **requirements met**
or **requirements unmet**, and its details list each requirement's verdict, the
failing commands with the end of their output, and what the gate decided. The
event history has a `task_requirements` row for every check.

A run on a device brings its tasks' records back with the tasks, and the hub
records them as its own requirement checks, read under the same rules and
against the hub's definitions. A requirement the hub changed while the run was
away is not recorded, because the run checked something the project no longer
requires.

### Regressions

A requirement that was fulfilled at its previous check of the same definition
and fails now is a **regression**: something has broken it since. The previous
check is the one before the task got to it (a task's own failing attempts do
not count), so a regression that a task caused stays a regression through its
retries. A regression is marked on the check and on the task (and in the next
attempt's prompt: "regression: it was fulfilled at commit …"), and written once
to the event history as a `requirement_regression` row naming the task, the
commit, and where the requirement last passed. A check that could not run, or
that nothing could verify, is not a verdict, and neither breaks nor sets the
baseline.

The approvals notifier can send regressions. A webhook in
`notifications.webhooks` that lists `requirement.regression` among its `events`
receives each regression: the project, the requirement, the task, the commit it
fails at and the one it last passed at, but never any test output. The event is
opt-in. A webhook with no `events` list, which gets every approval event, is not
sent regressions unless it names them.

```yaml
notifications:
  webhooks:
    - name: quality
      type: slack
      url_env: CLOOP_NOTIFY_QUALITY
      events: [requirement.regression]
```

## Red-green proofs

A check says whether a requirement's tests pass, but not whether they test
anything. A test that always passes makes a requirement look fulfilled when it
is not, and a test an agent wrote to pass will pass. A **proof** runs the
requirement's tests twice on the project's executor: once on the code before
the change, in a temporary checkout of the base commit, and once on the change
itself. The combined result of the two runs is recorded as the proof's outcome:

| Outcome | Meaning |
| --- | --- |
| **proven** | Red before, green after: the tests fail without the change and pass with it. |
| **vacuous** | Green before: they pass without the change too, so they do not show it. |
| **broken** | Red after: they do not pass on the change itself. |
| **inconclusive** | The test does not exist at the base, so the proof fell back to the base code plus the change's test files only, and that could not settle it: the command still does not run there (exit 127, or a test runner that found no test to run), or the change holds nothing but test files, so there is nothing for them to fail without. |
| **error** | The proof itself did not run: the base is not in the checkout, a run could not start, or it was stopped. Not a statement about the tests. |

```bash
cloop requirements prove R-3                  # against the commit before its test's implementation
cloop requirements prove 3 4 --base v1.2.0~1  # against a commit you name
```

`prove` exits 1 when a proof is vacuous, broken or could not run, so it can
gate CI too. In the dashboard, each tested requirement's card has a badge with
its latest proof (**unproven** until it has one) and a **Prove** button, and
its details list the recent proofs with both runs of each test.

### The base, and the fallback

For a task, the base is the commit the task's work started from. For a proof
you ask for by hand, it is the commit before the test's implementation: the
parent of the newest commit that changed the test's files (or of the newest
that changed a test the command names, such as `TestX` in `go test -run TestX`),
or the checkout's `HEAD` while those files have uncommitted changes. A test
committed on its own, in a commit that changed nothing but tests, is proved from
that commit. If the test was written first, its implementation came later, so
that commit holds the test but not yet the code. If it was written for what the
code already did, nothing after it changed what it tests, and the proof is
inconclusive. `--base` (or the API's `base`) names a different base.

A test that the change added or changed does not exist at the base in its new
form, and running the base as it is would run the old test, or none:
`go test -run TestNew` at a commit without `TestNew` passes with "no tests to
run". So the proof lays the change's test files over the base code, which runs
the new test against the old code, as red-green requires, and says so ("the
base run used the base code with the change's test files laid over it"). A
requirement's test files are the scripts its commands run
(`./scripts/check.sh`, `sh tests/r3.sh`) and the test files (`*_test.go`,
`test_*.py`, `*.test.ts`, anything under `tests/` or `testdata/`, …) at or
under the paths they name. A `cd dir &&` and a shell's `-c` line are followed.
A file that a command only reads, as in `grep -q done feature.txt`, is what the
test examines, not part of the test, and is never laid over the base. A command
that names no path at all, such as `npm test`, owns every test file the change
touched. A test that needs more of the change than its test files (a helper the
change added, for example) still does not run at the base, and the proof is
inconclusive.

The base run happens in a fresh checkout: files git ignores, such as
`node_modules`, are not there. A test command that needs them should install
them (`npm ci && npm test`). A test that only fails to compile without the
change counts as red, as it does in test-driven development.

### The project's checkout is never touched

The base's checkout is a detached linked worktree in the repository's
`.cloop/worktrees/proof-<random>`, beside the parallel tasks' worktrees. The
project's own checkout (its files, its index, its `HEAD`) is left as it was,
and the change's run happens in place, as a check's does. The worktree is
locked while the proof runs, so the hub's worktree sweep leaves it alone, and
it is removed however the proof ends: done, failed, cancelled or panicked. A
proof that is killed outright cannot remove it. The next proof in the
repository removes it, once the process that held it is gone or its deadline
has passed. Each run is limited by the tests' own timeouts, and the whole proof
by twice their sum.

### Proofs in the requirements gate

With the [requirements gate](#requirement-gated-completion) on, a check that
finds a task's work meets its requirements is followed by a proof of every
requirement in its scope whose tests the task added or changed (one of their
test files, or their test commands). The base is where the task's work started.
An attempt the gate sent back keeps the first attempt's base, so the second
attempt's test is not measured against the first attempt's implementation. The
check that just passed counts as the run on the change, so only the base run is
added. If a task leaves its requirements' tests alone, nothing is proved.

In `linked+must` mode, a **vacuous** proof of a test the task *added* (a new
test file, a test declared in a file it changed, or a new test command) keeps
the task from being done. The task goes back to pending, and its next prompt
names the test, the base and the test files, and asks for a test that fails on
the old code. A test that was only changed, as in a refactoring, is proved and
recorded but never blocks, and neither does a proof that is broken,
inconclusive or could not run. In `linked` mode, proofs are recorded and shown
but decide nothing.

Every proof is recorded with the project's requirement proofs (the gate's
proofs are tied to the task) and audited as `requirement.prove`. The task's
verdict keeps the proof. That is how a proof made on a device comes back to the
hub, which reads it again under its own rules.

## Traceability and spec coverage

The **traceability matrix** shows, for every approved requirement, what has
been done about it and how sure the project is that it holds, with one row per
requirement:

| Column | What it shows |
| --- | --- |
| Requirement | Its id, title, priority and tags, and its open gaps |
| Tasks | The tasks that [implement it](#tasks-that-implement-a-requirement), each with its state |
| Commits | The commits those tasks produced (below) |
| Latest verdict | Its latest check's verdict and method, how long ago, and whether it is **stale**: the requirement *changed since*, or tasks were *done since*; the task the check was made for, if the requirements gate made it |
| Proof | Its latest [red-green proof](#red-green-proofs), stale when it was of tests it no longer has |
| Verified | **tested** (it has tests), **model-assessed** (no tests; its latest verdict is the model's reading of the code), **person-assessed** (no tests; a person recorded its verdict) or **unverified** (no tests, and nothing reached a decision about it) |

A check or a proof keeps naming the task it was made for after that task is
deleted. The matrix shows such a task as **deleted** instead of dropping it.

### The commits

A requirement's commits are its tasks' commits, from two places:

- What each task records of its own work: the commit an isolated executor left
  it at, which the hub fetched back (`write-back`), and the commit the
  requirements gate checked it at, if that moved past where the task started
  (`gate`).
- The commit-to-task trace in `.cloop/trace.json`, which `cloop trace` writes
  (`trace`). A commit whose subject names its task (`(Task 12)`,
  `(Tasks 12, 13)`, or `cloop(task-12): …` as cloop's git workflow writes it) is
  linked to that task without asking a model. `cloop trace --no-model` links
  only those commits.

```bash
cloop trace --no-model --limit 200   # link the recent history to its tasks
```

The task a gate check was made for contributes none of its commits. In
`linked+must` mode the gate checks every must requirement at every task, so that
task says nothing about which requirement it implements. A deleted task's links
were deleted with it, so it implements nothing and contributes no commits.

### Spec coverage

The coverage sums up the rows, for the must requirements and for every approved
one:

| | A requirement counts when |
| --- | --- |
| **Tested** | it has at least one test |
| **Proven** | its latest proof is proven, and of the tests it has now |
| **Passing** | its latest check of its current definition found it fulfilled |
| **Linked** | at least one task in the plan implements it |

Percentages are rounded down, so 100% means all of them. A verdict that is
stale because tasks were done since then still counts as passing, because it is
about the requirement as it stands, and is also counted as stale. A verdict
about an earlier definition does not count as passing.

### Filters and pages

The matrix filters by **priority** (`must`, `should`, `could`, or `none`), by
**tag**, and by **gap** (`unfulfilled`, `stale`, `untested`, `unlinked`,
`unchecked`, or `none` for the requirements with no gap). It is read one page at
a time in id order, as a keyset page of the project's database that finds its
first row through an index. The priority and tag filters are applied in SQL. A
gap filter needs the plan, so it is applied by reading on until the page is
full. The coverage always covers every approved requirement, whatever the
filter.

### In the dashboard

The Requirements tab's **Traceability** button shows the matrix. Above it are
the coverage of the musts (tested, proven, passing, linked), a chip for each
kind of open gap that filters to it, and the filters. The rows are a table on a
desktop and one card per requirement on a phone. **Load more** reads the next
page. A requirement's id opens it in the list, and a task's number opens the
task.

The project's Overview has a **Spec coverage** card that shows how many musts
pass and how many are tested, proven and linked, and opens the matrix. Neither
of them polls. Whenever the hub notices a change to the project's database
(from a run, the CLI or the dashboard), it recomputes the coverage for any
project somebody has open and pushes it, with a digest of the whole matrix, as
`requirements_coverage`. The card redraws from the push, and an open matrix
reads its rows again only when the digest has changed.

### From a terminal and in reports

```bash
cloop requirements trace                          # the coverage, and a few lines per requirement
cloop requirements trace --priority must --gap unlinked
cloop requirements trace --json                   # rows, coverage, the next page's cursor
cloop requirements trace --markdown > TRACEABILITY.md
cloop requirements trace --csv > trace.csv
cloop requirements trace --limit 50 --after 120   # one page
```

Without `--limit` it prints every row. A CSV cell that would start a formula
(`=`, `+`, `-`, `@`) is prefixed with `'`, because anyone can write titles and
commit subjects. `cloop report`, in every format, includes the spec coverage
when the project has an approved requirement.

The same matrix is available as `GET /api/requirements/trace` (`project.read`,
scoped to the project). `priority`, `tag` and `gap` filter it, `limit` sets the
page size (50 unless asked, at most 200, `0` for the coverage alone), and
`after` is the `next` value from the previous page. The first page (without
`after`) also carries the `coverage`, how many rows `matched` the filter, and
the `digest`.

## Requirements as code

The dashboard keeps requirements and their checks in the hub's database. That is
not a place where you can review a change in a pull request, keep a requirement
beside the code it governs, or let a CI job without a hub gate on them. So a
project can also keep its requirements in a **spec file**,
`.cloop/requirements.yaml`, committed to its repository.

```yaml
version: 1
requirements:
  - id: R-3
    title: Config errors exit non-zero
    status: approved
    priority: must
    tags: [cli, config]
    details: |
      A malformed config.yaml makes every command exit 2
      and name the line.
    tests:
      - name: malformed config
        command: go test ./pkg/config -run TestMalformed
        timeout: 2m
  - id: R-4
    title: Rollbacks never lose a config
    status: draft
```

| Key | | What |
| --- | --- | --- |
| `version` | required | `1`, the format's version. A newer one is refused with "upgrade cloop". |
| `requirements` | required | The list; `[]` for none. |
| `id` | required | `R-<number>`. An id always refers to the same requirement: a new requirement gets a number that no requirement of the project has ever had. |
| `title` | required | One line. |
| `status` | required | `draft`, `approved` or `deprecated`. |
| `priority` | | `must`, `should` or `could`. |
| `tags` | | A list: letters, digits and `-_.:/`, lower-cased. |
| `details` | | What the requirement means: the dashboard's **Details**, `description` in the API. |
| `tests` | | A list of `command` (required), `name` and `timeout` (`90s`, `10m`, `1h30m`; 10 minutes when left out, at most 2 hours). |

The file is read strictly, because a requirement's tests are commands that run.
A misspelt key would otherwise be dropped without an error, and `test:` instead
of `tests:` would give a requirement that checks nothing and passes every gate.
So an unknown key is an error, and so are a key or an id given twice, a YAML
anchor, alias or tag, a second document, and any field outside the bounds the
database applies to a requirement ([Limits](#limits)). Every problem is
reported, each with its line:

```console
$ cloop requirements validate
Error: .cloop/requirements.yaml is not a valid requirements spec (2 problems):
  .cloop/requirements.yaml:3:5: R-1 has no title
  .cloop/requirements.yaml:4:5: R-1 has an unknown key "titel" (did you mean "title"?): the keys are id, title, status, priority, tags, details, tests
```

The file lives under `.cloop/`, beside `sandbox.yaml`. If your `.gitignore`
names `.cloop/`, git ignores the file, and git cannot re-include a file whose
directory it ignores. Ignore `.cloop/*` instead, and add
`!.cloop/requirements.yaml`. `export`, `validate` and the dashboard warn when
git ignores the file.

### Export and import

```bash
cloop requirements export             # write .cloop/requirements.yaml from the hub's requirements
cloop requirements import --dry-run   # what importing the file would do
cloop requirements import             # merge the file's changes into the hub
cloop requirements validate           # check the file, line by line
```

**Export** writes every requirement, including drafts and deprecated ones,
sorted by id in one fixed layout, so a change to one requirement shows up as a
change to its own lines in a diff. Comments in a file written by hand are not
kept. Export refuses to overwrite a file that has changes the hub does not have,
and lists them: import them first, or pass `--force` to discard them.
`--file -` prints the file instead of writing it.

**Import** does a three-way merge of the file into the hub, against the
**base**: the requirements as the file and the hub last agreed on them. A
change made on one side only is taken from that side:

| The requirement | Import |
| --- | --- |
| alike in the file and the hub | nothing |
| changed, added or deleted in the file only | changes, adds (under its id) or deletes it in the hub |
| changed in the hub only | leaves it: the next export writes it to the file |
| changed in both, in different fields | applies the merge: each side's change to the fields only it changed |
| changed in both in the same field, deleted on one side and changed on the other, or added on both sides differently | a **conflict** |
| added in the file under the id of a requirement the hub deleted | **refused**: renumber it |

Conflicts are never resolved automatically. Nothing is imported until every
conflict is resolved, with `--resolve R-<n>=file` (take the file's version:
delete the requirement if the file deleted it, restore it under its id if the
hub deleted it) or `--resolve R-<n>=hub` (keep the hub's version for the next
export), or all at once with `--prefer file|hub`. An import is all or nothing,
and is recorded as one `requirement.import` row that lists what it added,
changed, restored and deleted, and how each conflict was resolved. A
requirement deleted by an import is deleted along with the history of its
checks, as one deleted in the dashboard is.

The base moves on every import (to the file it imported), every export (to what
it wrote), and every read of the file that finds a requirement the same on both
sides. Whether a requirement has "changed" is decided by fingerprint: the
fingerprint a verdict is recorded against, plus the priority, tags and status
the file adds. Only a requirement whose three fingerprints all differ is merged
field by field. A project keeps one spec file. `--file` names another path for
a single command, and uses the same base.

### In CI, without a hub

`check --file` reads the requirements from the spec file and runs the tests of
the approved ones. It works in a checkout with no `.cloop/state.db`, creates
none, and records nothing:

```yaml
- name: The spec file is valid
  run: cloop requirements validate
- name: Requirements still hold
  run: cloop requirements check --file .cloop/requirements.yaml
```

It exits 1 when a requirement is unfulfilled, when its check did not work, or
when the file does not validate. A requirement with no tests is skipped unless
`--ai` asks the model. `--status` and `--all` also check drafts and deprecated
requirements. `--json` prints the report framed for a tool, with the table's
contents on stderr as each requirement is checked, so that a long check in a CI
log shows what it is doing, and with the same exit status. (Only the hub's own
dispatch, `--spec`, exits 0 whatever the check found, because the hub reads the
verdicts itself.)

cloop checks itself this way. Its repository's `.cloop/requirements.yaml` holds
the guarantees this documentation makes (the hub starts no process on its own
host except through an executor, every mutating route enforces RBAC, the hub's
environment never reaches a sandbox, migrations stay additive, and more), each
pointing at the test that proves it. Its CI runs `make requirements-check` on
every push. CONTRIBUTING.md explains how to add a new guarantee.

### In the dashboard

The Requirements tab shows the spec file in the project's checkout, wherever
the project's executor has it: a container's workspace, a device's directory, a
Pod's clone. The hub never opens the file on its own host. It dispatches
`cloop requirements validate --json` to the project's executor, with the
project's lease, in the same way as it dispatches a check, and parses the
printed bytes itself instead of trusting the executor's reading of them
(`TestTheHubReadsTheSpecFileOnlyOnTheProjectsExecutor` in `tests/security`). If
the executor runs a `cloop` older than the hub, the tab says so.

For somebody who may import, the tab reads the file again when it opens if the
last read is more than five minutes old (hourly for a checkout that had no
file). **Read again** reads it immediately. What it found is shown above the
list:

- **Spec changed**: the file has changes to import, or conflicts. **Review**
  lists each one with the hub's and the file's values of the fields that
  differ, and a choice for each conflict. **Import** applies exactly what was
  reviewed (the file whose SHA-256 it shows, and the plan it listed), or is
  refused with the new plan if either changed in the meantime.
- **The hub has changes the file does not**: use **Download
  requirements.yaml**, or run `cloop requirements export`, and commit the file.
  Once the file in the checkout matches the hub, the next read finds them in
  agreement.
- Problems, with their lines, when the file does not validate; a note when git
  ignores the file or it has uncommitted changes; and nothing when the file and
  the hub agree.

## Who may do what

| Action | Permission |
| --- | --- |
| See the requirements, their checks and runs, and the spec file's state | `project.read` |
| See the traceability matrix and the spec coverage | `project.read` |
| Download the requirements as a spec file | `project.read` |
| Add, change or delete a requirement, record a verdict, add a task from one | `task.mutate` |
| Have the model draft requirements, approve drafts | `task.mutate` |
| Plan from the requirements | `task.mutate` |
| Lint the requirements by rule | `project.read` |
| Lint them with the model | `task.mutate` |
| Link a task to the requirements it implements | `task.mutate` |
| Set the requirements gate | `config.write` |
| Read the spec file again, and import it | `task.mutate` |
| Check them, prove their tests | `run.start` |
| Stop a check or a proof | `run.stop` |

A test is a command that runs in the project's sandbox, as a task does, and it
runs only when somebody who may start the fleet asks. A spec file can add tests,
so importing one needs `task.mutate`, as adding tests does, and reading it again
starts a workload on the project's executor. Every change to a requirement,
every import and every check run is recorded in the project's audit trail as
`requirement.create`, `requirement.update`, `requirement.delete`,
`requirement.import`, `requirement.check`, `requirement.prove`,
`requirement.verdict`, `requirement.draft` and `requirement.approve`; see
[Audit events](../reference/audit-events.md). The HTTP endpoints are under
`/api/requirements` and `/api/requirement-runs` in the
[HTTP API reference](../reference/http-api.md).

## Limits

| | |
| --- | --- |
| Requirements per project | 1,000 |
| Title | 300 characters, one line |
| Details | 8,000 characters |
| Tests per requirement | 16, each a command of at most 4,096 bytes |
| Tags | 16, each 64 characters of letters, digits and `-_.:/` |
| A test's run | 10 minutes by default, at most 2 hours |
| Output kept per test | its last 16 KiB |
| Checks kept per requirement | the newest 50 |
| Proofs kept per requirement | the newest 20 |
| A proof | each test's own timeout on each side; the change's test files laid over the base at most 256 MiB |
| Check runs kept per project | the newest 200 |
| A whole check | 6 hours |
| A spec file | 2 MiB, one YAML document of at most 1,000 requirements, each held to the bounds above |
| Requirements one task implements | 32 |
| A task's contract in its prompt | 96 KiB; the requirements past it are named, with where to read them |
| A requirements gate check | the tests' own timeouts, at most 6 hours |
| A task's record of its last gate check | 50 requirements; 4 KiB of output per failing test |
| What a re-queued task's prompt quotes of it | 24 KiB |
| Gate re-queues in a row | `--max-verify-retries` (default 2) |
| Text drafted from | 64 KiB |
| Requirements one draft proposes | 30 (12 unless told) |
| A drafted requirement's acceptance criteria | 10, each 500 characters |
| Tasks one plan from the requirements proposes | 20, the tasks for must gaps included |
| Tasks by template one brainstorm or evolve round adds for must gaps | 5 |
| The requirement status a planner is sent | 64 KiB; past it the least pressing requirements are left out and counted |
| A page of the traceability matrix | 50 rows unless asked, at most 200 |
| Tasks and commits one row of it names | 50 tasks and 30 commits; past them it counts what it left out |
| The commit-to-task trace it reads | `.cloop/trace.json`, at most 4 MiB, a regular file inside `.cloop` |

On an executor that shares the project's directory (a container sandbox that
bind-mounts it, or the hub's own host), the project's database is writable from
inside the sandbox, so anything a workload could write there is no more
trustworthy than the workload itself. The hub records a check only from the
report it reads back, checked again against what it asked for: the commands,
the requirement's fingerprint and every verdict of a tested requirement come
from the hub, not from the report.
