# Live check: moving a project to a device and back

`tests/projectmove` proves moves end to end on one machine: a container
executor, and a second agent on loopback. This kit runs the same moves against
a real device on another machine, over the network, through a hub of its own,
so nothing it does touches a production hub. It was written for, and first run
in, Task 20497 against the sgx device.

[`run.sh`](run.sh) does everything and tears everything down again:

- a hub on `127.0.0.1:18497` with its own `HOME`, `CLOOP_HOME`, directory and
  API token, from the cloop under test (`BIN`, a static build);
- the project's origin, a bare repository served over TLS by
  [`forge.go`](forge.go) through git's own HTTP backend on `127.0.0.1:18498`;
- `ssh -R` for both ports, so the device's agent dials the hub on its own
  loopback and fetches the origin the same way, trusting the forge's
  certificate through `GIT_SSL_CAINFO`;
- a second agent on the device under `/tmp/cloop-projectmove-rig`, started as
  root with `env -i`, with the cloop under test and the stand-in
  [`claude`](claude) first on its `PATH`. The device's own agent is left alone;
- a Claude credential granted to the project first, because the hub refuses to
  dispatch a claudecode run to a device without one. The stand-in ignores it,
  so a placeholder token does.

```bash
CGO_ENABLED=0 go build -o /tmp/cloop-static .
BIN=/tmp/cloop-static DEVICE=sgx scripts/e2e/projectmove/run.sh
```

It runs every local cloop from its own work directory: a cloop started in the
repository's root opens and migrates the hub database there.

## The checks

Each move starts with a task held in progress by the stand-in, a commit on
`main` and one on the feature's branch that no remote has, and a dirty tree: a
modified, a deleted, a staged rename, an untracked and a binary file, and a
staged change edited again. [`snap.sh`](snap.sh) prints the facts a move must
carry (HEAD, every branch and tag, the index, every file git does not ignore,
the delivered `.cloop` files) on both machines, and the two are diffed.

| Step | Expected |
| --- | --- |
| move the project from the hub to the device with `cloop executor move` | done and verified; the held task pending again |
| `snap.sh` on the hub before, on the device after | identical, apart from the held task's own run output |
| the hub's copy after the move | unchanged until cleanup |
| run the project on the device | the held task done, from the moved working copy (HEAD still on `main` with the unpushed commit), its report attached, the first task's attachment kept |
| `cloop executor move cleanup` | the move's hidden refs gone, the hub's directory kept |
| the preflight for the move back | "still holds the copy the project left there" |
| move it back to the hub | done and verified; the hub identical to the device, with the feature branch the hub moved on in the meantime kept and its worktree clean |
| run the project on the hub | the held task done in the hub's directory |
| clean up the move back | the device's working copy removed |

`results.log` in the work directory has every check and the full output of
each `cloop executor move`.

## Last run

2026-11-15, the cloop of the Task 20497 commit (built from the working tree
before it was committed, so it reports `dev+gc8b09d0.dirty`) as both the hub and
the device's agent, against sgx (`Linux sgx 6.8.0-79-generic`, git 2.43.0): all
18 checks passed. Each move took about four seconds; the longest phase was the
device's seed, one second over the tunnel. An earlier run of the same day, on
the build before the review fixes, passed too.

## Traps

- The device's working copy is named after the project's path on the hub
  (`executor.DeviceWorkDir`), not after anything on the device: read it from
  the move's `detail.seed.work_dir`.
- A move back finds the hub's directory still holding the copy the first move
  left. That is expected, and the move rebuilds it in place only while it is
  unchanged: touching files in the hub's copy between the moves blocks it.
- `ssh -R` must come up before the agent starts, or the agent's first connect
  fails and it waits out its backoff. The script uses
  `ExitOnForwardFailure=yes` so a port already taken on the device fails fast.
- Kill the device's agent by the PID it wrote (`agent.pid`). Matching its
  command line with `pkill -f` would also match the production agent's.
