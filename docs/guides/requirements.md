# Requirements

A task says what to do next. A **requirement** says what the project must keep
doing, however many tasks later: "a malformed config makes every command exit
non-zero", "every API route declares a permission", "rolling back restores the
previous version byte for byte". Requirements belong to a project, live in its
database beside the plan, and are what you check to find out whether work that
was done is still done.

A requirement may have **tests**: shell commands, run in the project's root,
that pass when they exit 0. Checking a tested requirement runs them. A
requirement with no tests can be **assessed by the model**, which reads the
code and says whether it holds, or given a **verdict by hand**.

A requirement is a **draft**, **approved** or **deprecated**, and a check checks
the approved ones unless it is told otherwise. Requirements can also be kept
**as code**, in `.cloop/requirements.yaml` beside the code they govern, reviewed
in pull requests and checked by a CI job with no hub — see
[Requirements as code](#requirements-as-code).

## Adding requirements

From the dashboard, open a project's **Requirements** tab and press
**+ Add requirement**: a title, the details (what it means — and what the model
reads when there is no test to run), the tests one command per line, a
priority (`must`, `should`, `could`), a status and tags.

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
`cloop requirements remove <id>` deletes it with the history of its checks.
Requirements are numbered `R-1`, `R-2`, … and a number is never given to a
second requirement after the first is deleted, so a verdict, an audit row or a
task that names `R-7` names one requirement for good. A spec file is held to
the same rule.

### Statuses

| Status | Means | Checked |
| --- | --- | --- |
| **draft** | proposed, not yet agreed | only when named |
| **approved** | the project must keep it | by every check, unless told otherwise |
| **deprecated** | no longer required; kept for its history | only when named |

A requirement added without a status is approved, and every requirement written
before statuses existed is approved, so nothing that was checked stops being
checked. **Check all** and `cloop requirements check` with no ids check the
approved requirements; naming a requirement (**Check** on its card,
`cloop requirements check 4`) checks it whatever its status, and
`--status draft,approved` or `--all` widens a check from the terminal.
Approving or deprecating a requirement does not make its verdicts stale: it
still says the same thing.

### Writing tests

A test is a command for `/bin/sh -c`, run in the project's root with the
environment of the workload that checks it, plus `CLOOP_REQUIREMENT_ID` and
`CLOOP_REQUIREMENT` (`R-<id>`). Point it at the narrowest thing that proves the
requirement — a single test function, a script in the repository — rather
than the whole suite: a check runs every test of every requirement, one after
another.

- **Timeout.** Each test may run for 10 minutes unless it says otherwise (at
  most 2 hours). A test that runs out of time is an *error*, not a failure:
  the check could not say.
- **Nothing is left running.** A test runs in a process group of its own, and
  the whole group is killed when it ends, however it ends. A test that starts a
  server in the background and exits takes the server with it.
- **Output.** The last 16 KiB of what a test printed, stdout and stderr
  together, is kept with its result — the end is what says why a test failed.
  It is scrubbed first: the credentials leased to the workload, anything shaped
  like a credential, and the hub's root key, which never reaches a test's
  environment at all.
- **Size.** A requirement and its tests must fit in 64 KiB as the hub sends
  them; put a long command in a script in the repository and call that.

## Checking whether they are still fulfilled

Press **Check all** in the Requirements tab — it checks the approved
requirements — or **Check** on one requirement.
The check runs where the project's runs run: the hub dispatches
`cloop requirements check` to the project's executor — its container sandbox,
its device, its Pod — with the project's lease, firewall and resource limits,
exactly as it dispatches a task. The hub never runs a requirement's tests on
its own host, unless that is where the project's tasks run too
(`executors.allow_host_process`).

A check runs in the background: the tab shows it while it runs, updates as
each batch of requirements is recorded, and survives the tab that started it
being closed. **Stop** ends it. One check runs at a time per project, on
whichever hub member it was asked of; a second is refused with the one
running. A check whose hub member stopped is recorded as failed, and one whose
member died lapses at its deadline (the sum of its tests' timeouts, at most six
hours).

From a terminal:

```bash
cloop requirements check          # every approved requirement
cloop requirements check 3 R-5    # just these, whatever their status
cloop requirements check --all    # every requirement
cloop requirements history 3      # its recent checks, newest first
```

`cloop requirements check` exits 1 when a requirement is unfulfilled or its
check did not work, so it can gate a CI job — with the project's database, or,
with `--file`, from the spec file alone
([In CI, without a hub](#in-ci-without-a-hub)).

Run by hand it records what it finds in the project, as `cli:<user>` on the
executor `local`.

### Verdicts

| Verdict | Means |
| --- | --- |
| **fulfilled** | every test passed — or the model, or a person, said it holds |
| **unfulfilled** | a test failed — or the model, or a person, said it does not hold |
| **unverified** | the model was asked and could not tell |
| **error** | the check did not work: a test timed out or could not start, the executor's `cloop` sent back nothing (an executor running a `cloop` older than the hub says so) |

A requirement with no tests is **skipped** by a check that does not ask the
model, and its last verdict stands. Each recorded check carries the commit the
tree was at, whether it had uncommitted changes, where it ran and who asked.

### Requirements nothing tests

Tick **Ask the model about untested ones** before **Check all**, press **Ask
the model** on the requirement, or run `cloop requirements check --ai`. The
model is given the requirement's title and details and asked whether the code
in the project fulfils it; it answers with a verdict, a short rationale and the
places in the code it rests on. A provider that is an agent harness (Claude
Code, Copilot) reads the tree itself; any other is shown the files most related
to the requirement. On a hub with single sign-on the model runs on the account
of whoever asked, and a sandbox with no Claude credential for them is refused
before anything starts, with the dialog that grants one.

Or record what you found yourself: open the requirement's **Details** and press
**Mark fulfilled** or **Mark unfulfilled** with a note, or

```bash
cloop requirements verdict 4 fulfilled --note "rolled back staging twice"
```

### When a verdict is stale

A verdict is about the requirement as it read when it was checked. The tab
marks it **stale**

- when the requirement has been **changed** since — its title, details or
  tests; the verdict is about something it no longer says;
- when **tasks have been done** since the check: the code may have moved under
  it. Check again.

## Turning a failure into work

A requirement's **Details** offer **Add a task to restore it**, which adds a
pending task quoting what failed — the failing tests and the end of their
output — and the commands that will show it is fixed. A requirement with no
tests also offers **Add a task to test it**: the agent writes a test that
passes exactly when the requirement holds and names the command that runs it,
which you then add to the requirement. Either task is placed by the
requirement's priority: a `must` ahead of the plan's usual work, and either
[implements the requirement](#tasks-that-implement-a-requirement), so its run
is held to it. A deprecated requirement offers neither.

## Tasks that implement a requirement

A task can be linked to the requirements it implements. When the task runs,
its agent is given each one — title, details and test commands — as the task's
**acceptance contract**: the task is done only when those tests pass, run from
the project's root, and they must not be weakened to get there — not edited,
skipped, disabled or loosened, and the requirement not narrowed. An agent that
cannot make a test pass, or finds it wrong, is told to say so and end the task
as failed. A requirement with no tests is part of the contract through its
details. The requirements are read when the task starts, so an edit made while
it waited is the one it is held to.

Link a task from its **Edit** dialog, which lists the project's approved
requirements (and any the task already implements) to tick; from a terminal:

```bash
cloop task add "Make config errors exit non-zero" --no-ai --requirement R-3
cloop task edit 12 --requirement R-3,R-7    # replaces the task's list
cloop task edit 12 --requirement none       # clears it
cloop task show 12                          # "Implements: R-3, R-7"
cloop requirements show R-3                 # lists the tasks that implement it
```

or through the API, where `POST /api/task/add`, `POST /api/tasks`,
`POST /api/task/edit` and `PUT`/`PATCH /api/tasks/{id}` take `requirements`, a
list of ids — `3` or `"R-3"`. On an edit it replaces the task's list, `[]`
clears it, and leaving it out leaves the list alone.

A task's card shows a chip for each requirement it implements — **R-3** — that
opens the requirement, and a requirement's **Details** list the tasks that
implement it, each opening the task.

Requirement ids are the project's own, so a link is always to a requirement of
the task's own project: an id the project has no requirement for — mistyped,
deleted, or one that only another project has — is refused with a 400 (the CLI
exits non-zero), and so is a new link to a deprecated requirement. A link made
before its requirement was deprecated stays until it is removed; the contract
names the requirement and leaves it out. Deleting a requirement — from the
dashboard, with `cloop requirements remove`, or by importing a spec file that
no longer has it — takes it out of every task that implements it, in the same
transaction: the `requirement.delete` (or `requirement.import`) audit row names
the tasks (`unlinked_tasks`), and each gets its `task.upsert` row under the
same actor.

A run on an executor that does not share the hub's database — a device, a
Pod — receives the requirements its plan's unfinished tasks implement with the
project, so its agent is given the same contract. A plan file
(`cloop plan export`) carries no links: their ids would name other
requirements, or none, in the project that imports it.

## Requirement-gated completion

The contract tells the agent which tests must pass. The **requirements gate**
checks that they do, instead of taking the agent's `TASK_DONE` for it. It is
off by default and set per project, to one of three modes:

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
Options: each press moves it on from off to linked to linked+must and back to
off. The **Assess Untested** badge beside it switches the model's assessment
on and off. It can be declared in `.cloop/config.yaml` too:

```yaml
requirements:
  gate: linked+must   # off | linked | linked+must
  assess: false       # ask the model about linked requirements without tests
```

`cloop run` applies a declared gate to the project before it starts, so the
file stays the source of truth for a project that keeps one. The dashboard
control and `cloop requirements gate` rewrite the declaration when they change
a project that has one, so the two never disagree; a project whose
`config.yaml` declares nothing keeps whatever was set last. A mode the build
does not know is not read as `off`: it declares nothing, the project's own
setting stands, and every command that loads the file warns about it.
`cloop config set` and `cloop config validate` refuse an unknown mode outright.

Like "done means committed", the setting belongs to the project: it travels
with it to an isolating executor, and a run that is already going picks it up
at its next task.

### What happens when the agent reports done

When an attempt's turn ends in a way the orchestrator would accept as done —
`TASK_DONE`, or an unsignalled finish it would promote — the gate dispatches
`cloop requirements check --json --no-record --spec=<the requirements>` where
the run runs: on the project's executor, in the directory the agent worked in
(the task's worktree, in worktree-parallel mode), never on the hub's host. The
spec carries the requirements as the project defines them, and the report is
read back through the same rules the hub applies to a dashboard check:
commands, test names and fingerprints come from the project, and a tested
requirement's verdict is recomputed from its tests' outcomes, whatever the
report claims.

The check runs after "done means committed", so it tests committed work, and
before the review gate, which must not publish work whose requirements fail.
When the review gate's fix turns change the work, the requirements are checked
again before anything is pushed or merged; a failure then withholds the held
pushes, as a blocked review does.

What keeps a task from being done:

- a tested requirement whose tests fail, time out or cannot run — including a
  check the executor could not run at all;
- with `--assess`, a linked requirement without tests that the model finds
  unfulfilled.

A linked requirement without tests never blocks: it is reported
**unverified**, and nothing is dispatched for it unless the project asked the
model. A must requirement without tests is not checked in `linked+must` mode —
nothing but the model could tell whether it regressed, at a model call per
requirement per task — and the check says how many were left out. A deprecated
linked requirement is not checked.

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

The output is the end of what each failing test printed — at most 4 KiB a
test, 24 KiB in all — scrubbed of credentials, and quoted as data. The gate
sends a task back at most `--max-verify-retries` times in a row (default 2), the
same bound AI verification has; the attempt after that fails the task with
reason **`requirements_unmet`**, the failing checks as its diagnosis. Resetting
the failed task gives it the full count again. A task the gate sends back keeps
its worktree in worktree-parallel mode, so the next attempt fixes that work
rather than starting over.

Every outcome is stored before anything announces it, and the decision is the
task's verdict for stale-task recovery: while a check runs the verdict says
the requirements are being checked, so a run that dies mid-check has its task
run again rather than adopted done on the agent's word, and a decided
re-queue or failure is applied as the gate decided it. A run stopped while a
check runs returns the task to pending as interrupted.

### Where the verdict is recorded

Every gate check is recorded as the project's requirement checks, tied to the
task and the commit it ran at, under a check run whose source is `gate`, and
audited as `requirement.check`. The Requirements tab shows them like any other
check, naming the task ("for task #12"), and refreshes as they land. The task
keeps the gate's record of its latest check: its card shows **requirements met**
or **requirements unmet**, and its details list each requirement's verdict, the
failing commands with the end of their output, and what the gate decided. The
event history has a `task_requirements` row for every check.

A run on a device brings its tasks' records back with them, and the hub records
them as its own requirement checks — read through the same rules, against the
hub's definitions. A requirement the hub changed while the run was out is not
recorded: the run checked something the project no longer requires.

### Regressions

A requirement that was fulfilled at its previous check of the same definition
and fails now is a **regression**: something since broke it. The previous check
is the one before the task got to it — a task's own failing attempts do not
count — so a regression a task caused stays one through its retries. A
regression is marked on the check, on the task (and in the next attempt's
prompt: "regression: it was fulfilled at commit …"), and written once to the
event history as a `requirement_regression` row naming the task, the commit,
and where it last passed. A check that could not run, or that nothing could
verify, is not a verdict and neither breaks nor sets the baseline.

The approvals notifier can send them: a webhook in `notifications.webhooks`
that lists `requirement.regression` among its `events` is posted each
regression — the project, the requirement, the task, the commit it fails at and
the one it last passed at, never any test output. The event is opt-in: a
webhook with no `events` list, which gets every approval event, is not sent
regressions unless it names them.

```yaml
notifications:
  webhooks:
    - name: quality
      type: slack
      url_env: CLOOP_NOTIFY_QUALITY
      events: [requirement.regression]
```

## Requirements as code

The requirements in the hub's database are where the dashboard keeps them and
their checks, and no place to review a change in a pull request, to keep a
requirement beside the code it governs, or for a CI job with no hub to gate on.
So a project can keep them in a **spec file** as well:
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
| `id` | required | `R-<number>`. An id names one requirement for good: a new requirement takes a number no requirement of the project ever had. |
| `title` | required | One line. |
| `status` | required | `draft`, `approved` or `deprecated`. |
| `priority` | | `must`, `should` or `could`. |
| `tags` | | A list: letters, digits and `-_.:/`, lower-cased. |
| `details` | | What the requirement means — the dashboard's **Details**, `description` in the API. |
| `tests` | | A list of `command` (required), `name` and `timeout` (`90s`, `10m`, `1h30m`; 10 minutes when left out, at most 2 hours). |

The file is read **strictly**, because a requirement's tests are commands that
run: a misspelt key is a field silently dropped, and `test:` for `tests:` would
be a requirement that checks nothing and passes every gate. So an unknown key is
an error, as is a key or an id given twice, a YAML anchor, alias or tag, a
second document, and any field outside the bounds the database holds a
requirement to ([Limits](#limits)). Every problem is reported, each with its
line:

```console
$ cloop requirements validate
Error: .cloop/requirements.yaml is not a valid requirements spec (2 problems):
  .cloop/requirements.yaml:3:5: R-1 has no title
  .cloop/requirements.yaml:4:5: R-1 has an unknown key "titel" (did you mean "title"?): the keys are id, title, status, priority, tags, details, tests
```

The file lives under `.cloop/`, beside `sandbox.yaml`. A repository whose
`.gitignore` names `.cloop/` keeps it out of git — and git cannot re-include a
file whose directory it ignores — so ignore `.cloop/*` instead and add
`!.cloop/requirements.yaml`. `export`, `validate` and the dashboard warn when git
ignores the file.

### Export and import

```bash
cloop requirements export             # write .cloop/requirements.yaml from the hub's requirements
cloop requirements import --dry-run   # what importing the file would do
cloop requirements import             # merge the file's changes into the hub
cloop requirements validate           # check the file, line by line
```

**Export** writes every requirement — drafts and deprecated ones too — sorted by
id, in one fixed layout, so a change to one requirement is a change to its own
lines in a diff. Comments in a file written by hand are not kept. It refuses to
overwrite a file that has changes the hub does not, and names them: import them
first, or pass `--force` to discard them. `--file -` prints the file instead.

**Import** merges the file into the hub three ways — against the **base**, the
requirements as the file and the hub last agreed on them — so a change made on
one side only is that side's:

| The requirement | Import |
| --- | --- |
| alike in the file and the hub | nothing |
| changed, added or deleted in the file only | changes, adds (under its id) or deletes it in the hub |
| changed in the hub only | leaves it: the next export writes it to the file |
| changed in both, in different fields | applies the merge: each side's change to the fields only it changed |
| changed in both in the same field, deleted on one side and changed on the other, or added on both sides differently | a **conflict** |
| added in the file under the id of a requirement the hub deleted | **refused**: renumber it |

A conflict is never settled silently: nothing is imported until every one is
settled, with `--resolve R-<n>=file` (take the file's version — deleting it if
the file did, restoring it under its id if the hub did) or `--resolve R-<n>=hub`
(keep the hub's, for the next export), or all at once with `--prefer file|hub`.
An import is all or nothing, and is recorded as one `requirement.import` row
naming what it added, changed, restored and deleted, and how each conflict was
settled. A requirement deleted by an import goes with the history of its checks,
as one deleted in the dashboard does.

The base moves at every import (to the file it imported), every export (to what
it wrote), and every read of the file that finds a requirement the same on both
sides. "Changed" is decided by fingerprint — the fingerprint a verdict is
recorded against, with the priority, tags and status the file adds — and only a
requirement whose three fingerprints all differ is merged field by field. A
project keeps one spec file: `--file` names another path for one command, and
the base is the same.

### In CI, without a hub

`check --file` reads the requirements from the spec file and runs the approved
ones' tests, in a checkout with no `.cloop/state.db` — none is created — and
records nothing:

```yaml
- name: The spec file is valid
  run: cloop requirements validate
- name: Requirements still hold
  run: cloop requirements check --file .cloop/requirements.yaml
```

It exits 1 when a requirement is unfulfilled, its check did not work, or the
file does not validate. A requirement with no tests is skipped unless `--ai`
asks the model; `--status` and `--all` check drafts and deprecated ones too, and
`--json` prints the report framed, for a tool.

### In the dashboard

The Requirements tab shows the spec file in the project's checkout — which is
where the project's executor has it: a container's workspace, a device's
directory, a Pod's clone. The hub never opens the file on its own host: it
dispatches `cloop requirements validate --json` to the project's executor, with
the project's lease, exactly as it dispatches a check, and parses the bytes it
prints itself rather than take the executor's word for what they say
(`TestTheHubReadsTheSpecFileOnlyOnTheProjectsExecutor` in `tests/security`). An
executor running a `cloop` older than the hub says so.

The tab reads the file again when it opens and the last read is more than five
minutes old (hourly for a checkout that had none), for somebody who may import;
**Read again** reads it now. What it found shows above the list:

- **Spec changed** — the file has changes to import, or conflicts. **Review**
  lists each with the hub's and the file's values of the fields that differ, and
  a choice for each conflict; **Import** applies exactly what was reviewed —
  the file whose SHA-256 it shows, the plan it listed — or is refused, with the
  new plan, if either changed meanwhile.
- **The hub has changes the file does not** — **Download requirements.yaml**,
  or run `cloop requirements export`, and commit it. Once the file in the
  checkout says what the hub does, the next read finds them agreeing.
- Problems with their lines, when the file does not validate; a note when git
  ignores it or it has uncommitted changes; and nothing when they agree.

## Who may do what

| Action | Permission |
| --- | --- |
| See the requirements, their checks and runs, and the spec file's state | `project.read` |
| Download the requirements as a spec file | `project.read` |
| Add, change or delete a requirement, record a verdict, add a task from one | `task.mutate` |
| Link a task to the requirements it implements | `task.mutate` |
| Set the requirements gate | `config.write` |
| Read the spec file again, and import it | `task.mutate` |
| Check them | `run.start` |
| Stop a check | `run.stop` |

A test is a command that runs in the project's sandbox, which is what a task
already is; it runs only when somebody who may start the fleet asks. A spec
file can add tests, so importing one is `task.mutate`, as adding them is, and
reading it again starts a workload on the project's executor. Every change to
a requirement, every import and every check run is in the project's audit
trail: `requirement.create`, `requirement.update`, `requirement.delete`,
`requirement.import`, `requirement.check` and `requirement.verdict` — see
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
| Check runs kept per project | the newest 200 |
| A whole check | 6 hours |
| A spec file | 2 MiB, one YAML document of at most 1,000 requirements, each held to the bounds above |
| Requirements one task implements | 32 |
| A task's contract in its prompt | 96 KiB; the requirements past it are named, with where to read them |
| A requirements gate check | the tests' own timeouts, at most 6 hours |
| A task's record of its last gate check | 50 requirements; 4 KiB of output per failing test |
| What a re-queued task's prompt quotes of it | 24 KiB |
| Gate re-queues in a row | `--max-verify-retries` (default 2) |

On an executor that shares the project's directory — a container sandbox
bind-mounting it, the hub's own host — the project's database is writable from
inside the sandbox, so what a workload could write there is no stronger
evidence than the workload itself. The hub records a check only from the report
it reads back, rechecked against what it asked: the commands, the fingerprint of
the requirement and every verdict of a tested requirement come from the hub, not
from the report.
