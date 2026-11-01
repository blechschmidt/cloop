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
requirement's priority: a `must` ahead of the plan's usual work.

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

On an executor that shares the project's directory — a container sandbox
bind-mounting it, the hub's own host — the project's database is writable from
inside the sandbox, so what a workload could write there is no stronger
evidence than the workload itself. The hub records a check only from the report
it reads back, rechecked against what it asked: the commands, the fingerprint of
the requirement and every verdict of a tested requirement come from the hub, not
from the report.
