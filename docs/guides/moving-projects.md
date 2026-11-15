# Moving a project to another executor

A project runs on one executor at a time: the hub's own host, a container on
the hub, a remote machine you enrolled, or an executor pool. Changing the
binding in the dashboard only changes where the next run goes. Anything the old
side holds stays there: uncommitted changes, commits you never pushed, files a
run wrote under `.cloop`.

A move takes that work along. It stops the project's run, captures what the
old side holds, switches the binding, rebuilds the working copy on the new side
and checks it byte for byte before it counts as done. This page explains what a
move carries, how to read the check it runs first, and what to do when a move
can't go ahead or fails.

## Before you start

You need the `executor.manage` permission on the project and a place on the
target executor's access list. On a hub with single sign-on, a move also needs a
recent sign-in, so `cloop login` again if the hub asks for it.

A move names its target the way a binding does:

| Target | Means |
| --- | --- |
| an executor ID | a container executor, a remote machine, or a virtual executor on one |
| `pool:<id>` | an executor pool |
| `local` | the hub's own host (refused when `executors.allow_host_process` is off) |

Moving off a remote machine needs its agent to speak protocol v29 or later. The
preflight tells you when an agent is too old, and the Executors panel's
**Upgrade** button updates it.

## What a move carries

- **Uncommitted work:** staged and unstaged changes, deleted and renamed files,
  untracked files, binary files and the executable bit. On the target they are
  uncommitted changes again, staged where they were staged.
- **Every local branch and tag**, including commits no remote has, and stash
  entries.
- **Your features' branches.** A remote machine keeps each feature's working
  copy in a directory of its own; a move off the machine carries those too, as
  refs under `refs/cloop/move-feature/<move-id>/` in the project's repository.
  The hub's own feature worktrees are left as they are.
- **Files under `.cloop` that no database holds:** task output and artifacts,
  files a run left for attaching, checkpoints, `sandbox.yaml` and
  `requirements.yaml`.
- **The task in progress.** The move stops the run the way **Stop** does, so the
  task goes back to pending. Start the project on the target afterwards and it
  picks that task up.

The project keeps its path on the hub, because the path is how the hub knows
the project. Its grants, firewall rules, members, knowledge bindings and
requirements all stay valid. The plan, the history and task attachments live in
the hub's database and don't move at all.

On a remote machine, the next run starts from the working copy the move built:
the same branch, your unpushed commits and your uncommitted changes. Push from
there when the forge should have the work too. Two cases start from the forge
instead: a hub that pushes runs' work back (`executors.write_back: push`) pins
each run to the commit it measures the push from, and a project you bind to
another executor by hand and back again no longer counts the machine's copy as
its own.

## What a move never carries

- **Credentials.** The project's `.cloop/config.yaml` can hold API keys and
  stays where it is. Grants are not copied either: runs on the target get their
  credentials from the project's grants, the same way runs on the old side did.
- **Your harness login.** A Claude login or a Copilot sign-in on the hub never
  reaches a sandbox. A sandboxed target needs a harness credential granted to
  the project; the preflight tells you when it is missing (see
  [Secrets and egress](secrets.md)).
- **Files git ignores**, such as build output and `*.log`.
- **The hub's databases** and anything else under `.cloop` that isn't on the
  list above.

A capture from a remote machine is checked before anything switches. If it
contains a value one of the project's grants delivers (a token a run wrote into
a file, for example), the move fails at the capture. The error names the grant
and the file, never the value.

## Reading the preflight

Every move starts with a preflight, which changes nothing. Ask for one first:

```console
$ cloop executor move shop --to edge-01 --dry-run
Move preflight for shop (/srv/projects/shop)
  from executor local (localprocess) — hub_tree /srv/projects/shop
  to   executor edge-01 (remote) — device_working_copy /var/lib/cloop-executor/work/shop-1ad2f3f4

Nothing blocks the move: 0 warning(s), 7 carried.

→ [will-carry] The move stops the run in the project
→ [will-carry] 5 changed and 3 untracked path(s) no commit holds
→ [will-carry] 2 commit(s) on local branches no remote holds
      - cloop/feature/widget: 1
      - main: 1 — no upstream
    → Push them first if the forge should have them too.
→ [will-carry] 29 file(s), 16.0 MiB, under .cloop that no database holds
→ [will-carry] A run on the target gets its claudecode credential
→ [will-carry] 1 grant(s) reach the target
→ [will-carry] 2 record(s) are keyed by the project's path
```

In the dashboard, press **Move to…** on the project's **Executor** card: the
dialog shows the same report before you confirm.

Each finding has a severity:

- **Blocker:** the move can't start until you fix it. The line under the
  finding says how.
- **Will-carry:** something the move takes along, or that stays valid where the
  project goes.
- **Warning:** the move can go ahead, but something is lost, changed or could
  not be checked. You have to accept warnings: tick them in the dialog, or pass
  `--yes` on the command line.

The findings you are most likely to meet:

| Finding | What to do |
| --- | --- |
| The source cannot be reached | Start the remote machine's agent again. If the machine is gone for good, see [When the source is offline](#when-the-source-is-offline). |
| The device's agent is too old to capture the project | Upgrade the agent from the Executors panel. |
| A run on the target would not get its harness credential | Grant one to the project (the project's **Claude credential** card does it in one step). |
| A Pod would never see your changes | Kubernetes Pods build each run's tree from the forge. Commit and push, then move. |
| The hub's directory already holds files | Move those files aside. They are a copy on the hub, not the work you are moving. |
| The copy the project left in the hub's directory has changed since | See [Moving back to the hub](#moving-back-to-the-hub). |

## Moving

```console
$ cloop executor move shop --to edge-01 --yes
Moving shop to executor edge-01 (move eda2c82b2f0384de):
  ✓ preflight   100ms
  ✓ quiesce     500ms
  ✓ capture     200ms
  ✓ switch      0s
  ✓ seed        1s
  ✓ verify      400ms

Done: shop now runs on executor edge-01, and the hub verified it holds what was captured (11 refs, trees and files checked).
Kept: the hub keeps /srv/projects/shop as it was: the project's state, its features' worktrees and the working tree the move captured; runs now work on executor edge-01.
Remove what the move kept with: cloop executor move cleanup eda2c82b2f0384de
```

The phases are:

1. **preflight:** the check above, run again as the move starts.
2. **quiesce:** stops the project's runs and its features' runs. No run of the
   project starts until the move ends.
3. **capture:** writes the working tree's state, every branch and the `.cloop`
   files into the hub's move store.
4. **switch:** changes the binding, and narrows the project's firewall rules to
   what the target allows, in one step.
5. **seed:** rebuilds the working copy on the target.
6. **verify:** reads the target back and compares every branch, the index, the
   files on disk and each `.cloop` file with what was captured. Only a verified
   move is done.

Pressing Ctrl+C does not stop the move. Pick it up again with
`cloop executor move status <move-id>`. The dashboard shows each phase as it
happens, and the project's card says the project is moving.

## Moving back to the hub

When a project leaves the hub's own directory for a remote machine, the hub
keeps its copy of the project there: the project's state, its features'
worktrees, and the working tree as it was when the move captured it.

When you move the project back, the move recognises that copy. If nothing in
it has changed since the move that took the project away, the move rebuilds
the working copy in place, in the same repository. Your features' worktrees
stay where they are. If a feature's branch moved on while the project was away
(for example, because a feature run wrote its work back to the hub), the hub's
commits on that branch are kept, and the preflight says so.

If you changed files in the hub's copy while the project was away, the
preflight blocks the move and says what changed. Commit those changes on a
branch of their own, or move them out of the directory, and run the preflight
again. The move never overwrites changes it did not capture.

Files git ignores in the hub's copy, such as build output, stay where they
are. If the machine's copy has a file where the hub's copy has an ignored file
or directory, or anything else git doesn't track, the move stops before it
writes anything and names the path. Move that path aside and move again. The
same happens when a branch moved both on the hub and on the machine: the move
names the branch, and you choose which commits to keep before moving again.

## When the source is offline

A move from a remote machine has to ask its agent for the working copy, so a
machine that is offline blocks the move. Bring it back if you can: start the
agent, reconnect the machine, and run the preflight again.

If the machine is gone for good, move without it:

```console
$ cloop executor move shop --to local --abandon-source --dry-run
$ cloop executor move shop --to local --abandon-source --yes
```

With `--abandon-source` (or `abandon_source` in the API) the preflight lists
what is lost: the machine's uncommitted changes, its unpushed commits and its
`.cloop` files. The move captures nothing from it. The target starts from what
the hub and the forge have. Read that list before you pass `--yes`.

## Cleaning up

A finished move keeps three things until you clean up:

- its bundle and files in the hub's move store, under `.cloop/moves/<move-id>`
  in the hub's own directory;
- the hidden refs its capture wrote into the project's repository
  (`refs/cloop/move/<move-id>` and its neighbours);
- the source's copy: the hub's directory, or the remote machine's working copy.

```console
$ cloop executor move cleanup eda2c82b2f0384de
```

The command lists what it removes and asks first (`--yes` answers for you). It
removes the move store and the hidden refs, including the features' working
copies a move off a remote machine carried, so take anything you need from
those refs first. After a verified move from a remote machine, it also removes
that machine's working copy, but only if the copy still holds exactly what the
move captured, and never when the move carried features' working copies too. A copy with files git ignores is kept
unless you pass `--discard-ignored`. Pass `--keep-source` to leave the machine's
copy where it is; a later cleanup can still remove it. The hub's own directory
for the project is never removed, because it holds the project's state.

## When a move fails

A move that fails **before the switch** changed nothing. The project is still
bound where it was, and its source is untouched. The move says what went wrong,
for example a capture that carried a granted value. Fix that and move again.

A move that fails **after the switch** is rolled back: the old binding and the
old firewall rules come back in one step. The source is untouched, and the
move's bundle stays in the store. The target may hold a partial copy; the next
move of the same project to that target replaces it.

If the hub stops part-way through a move (a restart, a crash), the next hub
process picks the move up at the phase it reached. A step on a remote machine
waits up to two minutes for the machine's agent to reconnect before it gives
up. In a hub cluster, the member holding the machine's connection does that
step.

To see what happened, read the move:

```console
$ cloop executor move status eda2c82b2f0384de
```

It shows each phase, how long it took, which hub process ran it, and the error
that stopped the move. The audit trail has a row for the start, the switch, the
end and the cleanup of every move (`project.move.*`, see the
[audit events](../reference/audit-events.md)).

### Getting work back by hand

Everything a move captured is in its store until you clean up. If you need
something from it after a failed move, rebuild it in a scratch directory:

```console
$ bundle=/srv/hub/.cloop/moves/eda2c82b2f0384de/repo.bundle
$ git clone --quiet "$bundle" recovered && cd recovered
$ git fetch --quiet "$bundle" 'refs/cloop/*:refs/cloop/*'
$ git checkout main                                          # the branch you were on
$ git read-tree -u --reset refs/cloop/move/eda2c82b2f0384de  # the files as they were
$ git read-tree 'refs/cloop/move/eda2c82b2f0384de^2'         # what was staged
```

`git clone` warns that the bundle has no `HEAD` to check out; that is expected.

`git status` then shows the working tree as the move captured it. The `.cloop`
files are in `cloop-files.tar` beside the bundle.

## See also

- [Executors](../architecture/executors.md#before-a-project-moves): how the
  preflight is built and how a remote machine's working copy is captured.
- [Security model](../security/model.md#moving-a-project): what the capture path
  guarantees.
- [Virtual executors](virtual-executors.md): a machine and its virtual executors
  share one working copy, so moving between them moves nothing.
