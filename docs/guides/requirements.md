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

## Adding requirements

From the dashboard, open a project's **Requirements** tab and press
**+ Add requirement**: a title, the details (what it means — and what the model
reads when there is no test to run), the tests one command per line, a
priority (`must`, `should`, `could`) and tags.

From a terminal, in the project's directory:

```bash
cloop requirements add "Config errors exit non-zero" \
    -d "A malformed config.yaml makes every command exit 2 and name the line." \
    --test "go test ./pkg/config -run TestMalformed" --priority must --tag cli
cloop requirements add "Rollbacks never lose a config" --priority should
cloop requirements list
```

`cloop requirements edit <id>` changes one (`--test` replaces its tests,
`--clear-tests` removes them), `cloop requirements show <id>` prints it with
its latest check, and `cloop requirements remove <id>` deletes it with the
history of its checks. Requirements are numbered `R-1`, `R-2`, … and a number
is never given to a second requirement after the first is deleted, so a
verdict, an audit row or a task that names `R-7` names one requirement for
good.

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

Press **Check all** in the Requirements tab, or **Check** on one requirement.
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
cloop requirements check          # every requirement
cloop requirements check 3 R-5    # just these
cloop requirements history 3      # its recent checks, newest first
```

`cloop requirements check` exits 1 when a requirement is unfulfilled or its
check did not work, so it can gate a CI job:

```yaml
- name: Requirements still hold
  run: cloop requirements check
```

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
requirement's priority: a `must` ahead of the plan's usual work.

## Who may do what

| Action | Permission |
| --- | --- |
| See the requirements, their checks and runs | `project.read` |
| Add, change or delete a requirement, record a verdict, add a task from one | `task.mutate` |
| Check them | `run.start` |
| Stop a check | `run.stop` |

A test is a command that runs in the project's sandbox, which is what a task
already is; it runs only when somebody who may start the fleet asks. Every
change to a requirement and every check run is in the project's audit trail:
`requirement.create`, `requirement.update`, `requirement.delete`,
`requirement.check` and `requirement.verdict` — see
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

On an executor that shares the project's directory — a container sandbox
bind-mounting it, the hub's own host — the project's database is writable from
inside the sandbox, so what a workload could write there is no stronger
evidence than the workload itself. The hub records a check only from the report
it reads back, rechecked against what it asked: the commands, the fingerprint of
the requirement and every verdict of a tested requirement come from the hub, not
from the report.
