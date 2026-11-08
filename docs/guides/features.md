# Developing features in parallel

A cloop project has one task list and one set of run settings. That works for
one line of work, but not for three. Two features built in the same checkout
edit the same files, their tasks get mixed up in one plan, and you can't say
"keep evolving this one, but let that one finish and stop".

A **feature** solves all three problems. It is a git worktree of the project's
repository, on its own branch, with its own `.cloop/` directory. So it has its
own task list, its own run, and its own auto-evolve and innovate settings, and
any number of features can run at the same time as the project and each other.
When a feature is done, it becomes a pull request into the branch it was cut
from.

## What a feature is

```
<project>/                                  main — the project's own worktree
<project>/.cloop/features/dark-mode/        cloop/feature/dark-mode
<project>/.cloop/features/dark-mode/.cloop/ the feature's tasks, settings, history
<project>/.cloop/features/login/            cloop/feature/login
```

- **A worktree, not a copy.** `git worktree add` shares the repository's
  objects, so a feature costs only a checkout of the tree. Its branch is
  `cloop/feature/<slug>`, cut from the base branch (the remote's default branch
  unless you name another).
- **A project in its own right.** The orchestrator runs in the feature's
  directory like anywhere else. `cloop run`, `cloop task add` and every other
  command work there unchanged, and the dashboard lists the feature as a project
  of its own, nested under its parent.
- **Independent settings.** A feature starts with the project's provider, model,
  effort and instructions, and has its *own* auto-evolve, innovate and parallel
  settings. You can change them on the feature's Overview without affecting the
  project or its other features.
- **Told where it is.** cloop appends a note to the feature's instructions that
  names its branch and tells the agent to commit there and never push to or
  merge into the base. The branch's upstream is set to
  `origin/cloop/feature/<slug>`, so a harness that pushes out of habit publishes
  the feature and nothing else.
- **Locked.** The worktree is locked with `git worktree lock`, so neither cloop's
  task-worktree cleanup nor `git gc` can remove it while it is briefly
  unreachable. `cloop feature remove` unlocks it.

cloop also makes sure git ignores every worktree's `.cloop/`. If nothing already
ignores it, cloop adds `/.cloop/` to the repository's `info/exclude`. That way
neither the project nor a feature ever commits cloop's state, and the project
never records a feature as an embedded repository.

## In the dashboard

Open a project that is a git repository. Its Overview has a **Features**
section with one row per feature (branch, status, options, task progress and
pull request) and a **+ New feature** button.

The New feature dialog asks for a name and what the feature should achieve.
Optionally you can add initial tasks (one per line), a base branch, and the
feature's settings: auto-evolve, innovate, parallel tasks, open the pull request
when complete, and start now. Creating the feature opens it.

A feature's Overview starts with a banner naming its project and branch, with
**Open pull request** (or **Update pull request** once one is open) and
**Remove feature**. Everything below it (goal, options, tasks, run controls and
event history) belongs to the feature. On the Projects grid, features appear as
chips inside their project's card, and the header's project menu lists them
indented under the project.

## From the command line

```bash
cloop feature new "Dark mode" --description "Add a dark theme and a toggle" --innovate
cloop feature new login --task "Add a login form" --task "Hash passwords" --auto-pr
cloop feature list

cd .cloop/features/dark-mode && cloop run     # or start it from the dashboard

cloop feature pr dark-mode
cloop feature remove dark-mode --delete-branch
```

See the [command reference](../reference/commands.md#parallel-features) for every
flag. A feature created from a terminal appears in the dashboard on its next
refresh, because features are discovered from `.cloop/features` and never
registered.

## Pull requests

**Open pull request** pushes the feature's branch to `origin` and opens a
GitHub pull request from it into the feature's base branch. The title is the
feature's name. The description is its goal, the tasks it completed, and the
tasks it did not, so a reviewer can tell a finished feature from one proposed
early.

If you click it again while that pull request is open, it pushes whatever was
committed since, which updates the pull request. For a feature created with
**Open PR when complete** (`--auto-pr`), the hub opens the pull request as soon
as the feature's plan completes. The feature's event history records the pull
request, or why it could not be opened.

For a project the hub runs itself, the push uses whatever git credentials the
feature's executor has: the host's SSH keys or credential store, or the scoped
credential helper a repository grant installs. Only if that push fails and the
remote is https does cloop retry it with the API token described below, passed
to git in its environment and not on its command line. Opening the pull request
needs a token with pull-request access. cloop looks for one in this order:

1. `--token`;
2. `GITHUB_TOKEN`, then `GH_TOKEN`;
3. `github.token` in the feature's `.cloop/config.yaml` (copied from the
   project's);
4. git's credential helpers for the repository;
5. `gh auth token`;
6. `CLOOP_GITHUB_TOKEN`, the hub's own `github.token`. The hub offers it last,
   so a project's own credentials always come first, and only where it gives
   no extra access: on a hub without sign-in, for a project on an executor that
   shares the hub's host.

A token from the flag, the environment or a config file (1, 2, 3 and 6) is only
sent to github.com, or for GitHub Enterprise to the host that `--api-url` /
`CLOOP_GITHUB_API_URL` names. It is never sent to whatever server a remote
happens to point at, and an Enterprise token (whose `--api-url` is its
server's) is never sent to github.com. Reports only ever say where the token
came from. A repository assigned to the project with **write** access (see
[secrets and egress](secrets.md)) includes `pull_requests:write`.

For a project on an [isolating executor](#features-on-isolating-executors), the
hub publishes the feature itself, from the branch the runs' work was written
back to. None of the token sources above belong to the project there, so the
token is the project's own GitHub grant for the repository, leased for the push
and the API call and released straight after. On a hub without sign-in it is
the hub's `github.token`. The grant must be for the origin's host (`github.com`,
or the GitHub Enterprise Server its secret names), and the pull request is
opened at that grant's API (`api.github.com`, or the server's `/api/v3`), never
at one derived from the origin. If the origin is on another host, cloop refuses
with an error naming both hosts. A grant restricted to certain branches must
include the feature's (`cloop/*` does). No git proxy sits between the hub and
the forge, so the hub applies the branch list itself and refuses to push
anywhere else.

## Where a feature may run, and what it inherits

For every setting that decides *what the project may do* (as opposed to *what
it is working on*), a feature counts as its project:

| | Taken from |
|---|---|
| Executor it runs on | the project's binding |
| Resource ceiling | the project's |
| Secret grants (repositories, keys, env) | the project's |
| Who may see and operate it | the project's roles, owner and API-token scope |

Wherever such a decision is looked up by path, cloop maps the feature's path to
its project's. The mapping reads the parent from the path itself, so it fails
closed: a feature whose record is damaged still runs in its project's sandbox
with its project's grants, and never on the hub's default executor with none.
cloop refuses to bind a feature to another executor or to assign it
repositories of its own. Change these on the project.

The firewall rules a run gets, the [review gate](review-gate.md) and the
[git proxy](../architecture/git-proxy.md) also come from the project, and apply
to a feature's runs as they do to the project's.

## Features on isolating executors

A feature is a *linked* worktree: its `.git` is a one-line pointer to the
project's repository, by absolute path on the hub. On the hub that is all it
needs. Anywhere else, git does not recognise the directory: a container sees
the feature at another path, and a remote device does not see it at all. cloop
won't also hand the sandbox the project's `.git` to make the pointer work,
because hooks and configuration written there would run on the hub the next
time anything there ran git in the repository.

So on an executor that isolates from the hub (a
[container executor](enterprise-hosts.md), a remote agent, or a
[virtual executor](virtual-executors.md) on one), a feature travels as its
**branch**, and its work comes back the same way. This is what lets features run
on a hub with `executors.allow_host_process: false`, where there is no other
kind of executor.

**Out.** At each run the hub bundles the feature's branch (`git bundle`), and
the executor builds a standalone checkout of it from the bundle, on the branch
itself:

| The project's repository | What is shipped |
|---|---|
| Has an https upstream that already holds the feature's base, on an executor that can clone (a remote agent) | Only the feature's own commits. The executor clones the upstream at the feature's base with the project's GitHub grant, as it would clone the project, and applies the bundle on top. |
| Exists only on the hub, or its base was never pushed, or the executor cannot clone (a container on the hub) | The whole branch. If that is over the size limit, its newest 50 commits, and failing that its newest commit alone: a shallow checkout, with its boundary recorded. |

Either way the bundle is capped at `executors.feature_bundle_mb` (default 32,
at most 128). A branch that is too large even as one commit is refused with a
message naming the setting. The feature's own `.cloop` state (goal,
instructions, plan) travels beside it as for any project on an isolating
executor, and the feature's `.cloop/` is excluded from the checkout's commits.

**Back.** The harness commits on `cloop/feature/<slug>` in its checkout, as a
feature's harness is told to. When the run ends, its commits, plus anything it
left uncommitted (committed on top), come back as a write-back bundle onto that
branch, capped by the same setting. The run's task outcomes come back with the
project state. On the hub the bundle is fetched into quarantine and checked
before any branch moves. It must build on the exact commit the run was sent,
and no path in it may reach into `.git`, escape the tree through a symlink, or
be a submodule (see
[Features: shipping a branch](../architecture/executors.md#features-shipping-a-branch-task-20367)
and the [write-back checks](../security/model.md)).

The hub then fast-forwards the feature's worktree onto the work, but **only**
when the worktree is clean, still on its branch, and the work builds on its
HEAD. Otherwise the checked work is kept on a branch of its own,
`cloop/returned/<slug>/<run>`, and the feature records a conflict. Its row in
the parent's Features panel says "work kept on …", and its event history (and
the parent's) gives the reason: uncommitted changes in the worktree, a branch
that moved while the run was out, or commits that touch `.cloop/` (which in the
worktree is the hub's own copy of the feature's state). Nothing is ever forced.
Merge the kept branch when you are ready:

```bash
cd <project>/.cloop/features/<slug>
git merge cloop/returned/<slug>/<run>
```

A run that fails or is stopped part-way still returns the commits its earlier
tasks made, since each one was a checkpoint the agent chose to commit. It does
not return what the run left uncommitted, which may be a half-applied change.

**Managing the feature.** For such a project the hub creates, removes and
publishes features itself, because the executor cannot see the hub's worktrees
and so cannot run `cloop feature …`. Every git command the hub runs for this
(creating the worktree, bundling the branch, landing the work, pushing it for a
pull request) runs without system or global configuration, with the
repository's hooks, filters, fsmonitor and signing programs switched off, and
never in a sandbox's copy of anything.

**Which executors.** A container executor stages the checkout in a directory of
its own (never the hub's worktree), mounts it as `/workspace`, and runs the
write-back *inside* the container after the harness, so git never runs on the
hub in a repository the sandbox could write. Its sandbox image needs git and a
cloop of this release or later. A remote agent needs protocol v16 or later, and
git on its device. For an older agent, the error says how to move it forward
from this hub (see
[Moving a device forward](../architecture/executors.md#moving-a-device-forward-which-remedy-works)).
A Kubernetes executor can't run features, because the hub has no way to carry
the branch into a Pod. A feature bound to one, like a feature on an outdated
agent, is refused at dispatch with a 409 that says what is missing.

**Projects with no repository on the hub.** Some projects are bound to a remote
executor and their code is the repositories granted to them, cloned by the
harness on the device, with nothing on the hub but `.cloop/`. Such a project has
no branch for a feature to live on, and creating a feature in it is refused
with that reason. A design with a per-feature device directory and a feature
branch in each granted repository was considered and not built. It would need a
feature branch, a write-back and a pull request for every repository the
project holds, plus a place for the feature's state that is neither a worktree
nor the device's directory, which would amount to a second feature model. To
develop features of such a project, give it a repository of its own on the hub.

## Removing a feature

**Remove feature** deletes the worktree, and with it the feature's task list and
history. It is refused while the feature runs and while the worktree has
uncommitted changes (force discards them). The branch is kept unless you ask
for it to be deleted, and even then only if git considers it merged. A
squash-merged pull request doesn't count as merged, so deleting that branch
needs force.

cloop refuses to remove or unregister the project itself while any of its
features runs. Snapshots (`cloop snapshot`) don't archive feature worktrees and
don't touch them on restore, and `cloop clean` refuses while features exist
unless you pass `--force`.

## Limits

- A project may hold 32 features.
- Features are one level deep: a feature cannot have features.
- The project directory must be the top of its git repository.
- On an isolating executor, a feature's branch and the work a run returns are
  each capped at `executors.feature_bundle_mb` (default 32 MiB, at most 128).
