# Developing features in parallel

A cloop project has one task list and one set of run settings. That fits one
line of work. It does not fit three: two features built in the same checkout
edit the same files, their tasks interleave in one plan, and there is no way to
say "keep evolving this one, but let that one finish and stop".

A **feature** removes all three problems. It is a git worktree of the project's
repository, on its own branch, with its own `.cloop/` directory — so it has its
own task list, its own run, and its own auto-evolve and innovate settings — and
any number of them run at the same time as the project and as each other. When
one is done, it becomes a pull request into the branch it was cut from.

## What a feature is

```
<project>/                                  main — the project's own worktree
<project>/.cloop/features/dark-mode/        cloop/feature/dark-mode
<project>/.cloop/features/dark-mode/.cloop/ the feature's tasks, settings, history
<project>/.cloop/features/login/            cloop/feature/login
```

- **A worktree, not a copy.** `git worktree add` shares the repository's
  objects, so a feature costs a checkout of the tree and nothing more. Its
  branch is `cloop/feature/<slug>`, cut from the base branch (the remote's
  default branch unless you name another).
- **A project in its own right.** The orchestrator runs in the feature's
  directory like anywhere else: `cloop run`, `cloop task add` and every other
  command work there unchanged, and the dashboard lists the feature as a project
  of its own — nested under its parent.
- **Independent settings.** A feature starts with the project's provider, model,
  effort and instructions, and its *own* auto-evolve, innovate and parallel
  settings. Toggle them on the feature's Overview without touching the project
  or its other features.
- **Told where it is.** A note is appended to the feature's instructions: which
  branch it is on, that it must commit there and never push to or merge into the
  base. The branch's upstream is set to `origin/cloop/feature/<slug>`, so a
  harness that pushes out of habit publishes the feature and nothing else.
- **Locked.** The worktree is `git worktree lock`ed, so neither cloop's
  task-worktree cleanup nor `git gc` can collect it while it is briefly
  unreachable. `cloop feature remove` unlocks it.

cloop also makes sure every worktree's `.cloop/` is ignored by git — it adds
`/.cloop/` to the repository's `info/exclude` if nothing already ignores it — so
neither the project nor a feature ever commits cloop's state, and the project
never records a feature as an embedded repository.

## In the dashboard

Open a project that is a git repository. Its Overview has a **Features**
section: one row per feature with its branch, status, options, task progress and
pull request, and **+ New feature**.

The New feature dialog asks for a name and what the feature should achieve, and
optionally initial tasks (one per line), a base branch, and the feature's
settings: auto-evolve, innovate, parallel tasks, open the pull request when
complete, and start now. Creating it opens the feature.

A feature's Overview begins with a banner naming its project and branch, with
**Open pull request** (or **Update pull request** once one is open) and
**Remove feature**. Everything below it — goal, options, tasks, run controls,
event history — is the feature's own. On the Projects grid, features appear as
chips inside their project's card; the header's project menu lists them indented
under it.

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
refresh: features are discovered from `.cloop/features`, never registered.

## Pull requests

**Open pull request** pushes the feature's branch to `origin` and opens a
GitHub pull request from it into the feature's base branch. The title is the
feature's name; the description is its goal, the tasks it completed, and those
it did not — so a reviewer can tell a finished feature from one proposed early.

Asked again while that pull request is open, it pushes whatever was committed
since, which updates it. A feature created with **Open PR when complete**
(`--auto-pr`) gets its pull request from the hub as soon as its plan completes;
the feature's event history records either the pull request or why it could not
be opened.

For a project the hub runs itself, the push uses whatever git credentials the
feature's executor has — the host's SSH keys or credential store, the scoped
credential helper a repository grant installs. Only if that push fails, and the
remote is https, is it retried with the API token below, passed to git in its
environment rather than on its command line. Opening the pull request needs a
token with pull-request access, found in this order:

1. `--token`;
2. `GITHUB_TOKEN`, then `GH_TOKEN`;
3. `github.token` in the feature's `.cloop/config.yaml` (copied from the
   project's);
4. git's credential helpers for the repository;
5. `gh auth token`;
6. `CLOOP_GITHUB_TOKEN` — the hub's own `github.token`, which it hands over
   last, so that a project's credentials always come first, and only where it
   widens nothing: on a hub without sign-in, for a project on an executor that
   shares its host.

A token from the environment or a config file (2, 3 and 6) is only sent to
github.com, or to the host `--api-url` / `CLOOP_GITHUB_API_URL` names for
GitHub Enterprise — never to whatever server a remote happens to point at.
Only where the token came from is ever reported. A repository assigned to the
project with **write** access (see [secrets and egress](secrets.md)) includes
`pull_requests:write`.

For a project on an [isolating executor](#features-on-isolating-executors) the
hub publishes the feature itself, from the branch the runs' work was written
back to: none of the sources above belong to the project there, so the token is
the project's own GitHub grant for the repository — leased for the push and the
API call and released straight after — or, on a hub without sign-in, the hub's
`github.token`. A grant restricted to certain branches must include the feature's
(`cloop/*` does): no git proxy stands between the hub and the forge, so the hub
applies the list itself and refuses to push anywhere else.

## Where a feature may run, and what it inherits

For everything that decides *what the project may do* rather than *what it is
working on*, a feature is its project:

| | Taken from |
|---|---|
| Executor it runs on | the project's binding |
| Resource ceiling | the project's |
| Secret grants (repositories, keys, env) | the project's |
| Who may see and operate it | the project's roles, owner and API-token scope |

This is enforced by mapping the feature's path to its project's wherever such a
decision is keyed by path, and the mapping is lexical — the parent is read from
the path itself — so it fails closed: a feature whose record is damaged still
runs in its project's sandbox with its project's grants, never on the hub's
default executor with none. Binding a feature to another executor, or assigning
it repositories of its own, is refused; change them on the project.

The firewall rules a run gets, the [review gate](review-gate.md) and the
[git proxy](../architecture/git-proxy.md) are the project's too, and apply to a
feature's runs exactly as to the project's.

## Features on isolating executors

A feature is a *linked* worktree: its `.git` is a one-line pointer to the
project's repository, by absolute path on the hub. On the hub that is all it
needs. Anywhere else it is a directory git does not recognise — a container sees
the feature at another path, a remote device does not see it at all — and
handing the sandbox the project's `.git` as well, so the pointer resolves, is not
something cloop will do: hooks and configuration written there would run on the
hub the next time anything there ran git in the repository.

So on an executor that isolates from the hub — a [container executor](enterprise-hosts.md),
a remote agent, a [virtual executor](virtual-executors.md) on one — a feature
travels as its **branch**, and its work comes back the same way. This is what
lets features run on a hub with `executors.allow_host_process: false`, where
there is no other kind of executor.

**Out.** At each run the hub bundles the feature's branch (`git bundle`) and
the executor builds a standalone checkout of it, on the branch itself, from the
bundle:

| The project's repository | What is shipped |
|---|---|
| Has an https upstream that already holds the feature's base, on an executor that can clone (a remote agent) | Only the feature's own commits. The executor clones the upstream at the feature's base, with the project's GitHub grant, exactly as it would clone the project, and applies the bundle on top. |
| Exists only on the hub — or its base was never pushed, or the executor cannot clone (a container on the hub) | The whole branch. If that is over the size limit, its newest 50 commits, then its newest commit alone — a shallow checkout, with its boundary recorded. |

Either way the bundle is capped at `executors.feature_bundle_mb` (default 32,
at most 128); a branch too large even as one commit is refused with a message
naming the setting. The feature's own `.cloop` state — goal, instructions,
plan — travels beside it as for any project on an isolating executor, and the
feature's `.cloop/` is excluded from the checkout's commits.

**Back.** The harness commits on `cloop/feature/<slug>` in its checkout, as a
feature's harness is told to. When the run ends, its commits — and anything it
left uncommitted, committed on top — come back as a write-back bundle onto that
branch, capped by the same setting, and the run's task outcomes come back with
the project state. On the hub the bundle is fetched into quarantine and vetted
before any branch moves: it must build on exactly the commit the run was sent,
and no path in it may reach into `.git`, escape the tree through a symlink, or
be a submodule (see [Features: shipping a branch](../architecture/executors.md#features-shipping-a-branch-task-20367)
and the [write-back checks](../security/model.md)).

The hub then fast-forwards the feature's worktree onto the work — **only** when
the worktree is clean, still on its branch, and the work builds on its HEAD. In
every other case the work is kept, vetted, on a branch of its own,
`cloop/returned/<slug>/<run>`, and the feature records a conflict: its row in
the parent's Features panel says "work kept on …", and its event history (and
the parent's) says why — uncommitted changes in the worktree, a branch that
moved while the run was out, or commits that touch `.cloop/`, which in the
worktree is the hub's own copy of the feature's state. Nothing is ever forced.
Merge the kept branch when you are ready:

```bash
cd <project>/.cloop/features/<slug>
git merge cloop/returned/<slug>/<run>
```

A run that fails or is stopped part-way still returns the commits its earlier
tasks made — each was a deliberate checkpoint — but not what it left
uncommitted, which may be a half-applied change.

**Managing the feature.** For such a project the hub creates, removes and
publishes features itself rather than sending `cloop feature …` to the
executor, which cannot see the hub's worktrees. Every git command it runs for
this — creating the worktree, bundling the branch, landing the work, pushing it
for a pull request — runs with no system or global configuration and with the
repository's hooks, filters, fsmonitor and signing programs switched off, and
never in a sandbox's copy of anything.

**Which executors.** A container executor stages the checkout in a directory of
its own (never the hub's worktree), mounts it as `/workspace`, and runs the
write-back *inside* the container after the harness, so git is never run on the
hub in a repository the sandbox could write; its sandbox image needs git and a
cloop of this release or later. A remote agent needs protocol v16 or later
(`cloop executor agent install --upgrade`). A Kubernetes executor cannot run
features — the hub has no way to carry the branch into a Pod — and a feature
bound to one, like one on an outdated agent, is refused at dispatch with a 409
naming what is missing.

**Projects with no repository on the hub.** A project bound to a remote executor
whose code is the repositories granted to it — cloned by the harness on the
device, with nothing on the hub but `.cloop/` — has no branch for a feature to
be. Creating a feature of it is refused with that reason. A per-feature device
directory with a feature-branch convention in each granted repository was
considered and not built: it would need a feature branch in every repository the
project holds, a write-back and a pull request per repository, and a place for
the feature's state that is neither a worktree nor the device's directory — a
second feature model rather than this one carried further. Give the project a
repository of its own on the hub to develop features of it.

## Removing a feature

**Remove feature** deletes the worktree and with it the feature's task list and
history. It is refused while the feature runs and while the worktree has
uncommitted changes (force discards them). The branch is kept unless you ask
for it to go, and even then only if git considers it merged — a squash-merged
pull request is not, so deleting that branch takes force.

Removing or unregistering the project itself is refused while any of its
features runs. Snapshots (`cloop snapshot`) neither archive feature worktrees
nor touch them on restore, and `cloop clean` refuses while features exist unless
given `--force`.

## Limits

- A project may hold 32 features.
- Features are one level deep: a feature cannot have features.
- The project directory must be the top of its git repository.
- On an isolating executor, a feature's branch and the work a run returns are
  each capped at `executors.feature_bundle_mb` (default 32 MiB, at most 128).
