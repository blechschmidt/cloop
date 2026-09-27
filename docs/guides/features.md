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

The push uses whatever git credentials the feature's executor has — the host's
SSH keys or credential store for a local project, the scoped credential helper a
repository grant installs. Only if that push fails, and the remote is https, is
it retried with the API token below, passed to git in its environment rather
than on its command line. Opening the pull request needs a token with
pull-request access, found in this order:

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

A feature is a *linked* worktree, whose `.git` is a pointer to the project's
repository by absolute path. That pointer resolves only on a filesystem that
sees the project where the hub does, so features run on executors that share the
hub's filesystem — the local executor. A project bound to a container,
Kubernetes or remote executor cannot create features, and a feature whose project
is later moved to one is refused at dispatch with a 409 naming the constraint,
rather than started in a directory where git would not work.

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
