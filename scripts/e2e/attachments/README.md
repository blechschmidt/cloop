# Live check: attachments on a remote executor

A run on a remote executor works on its own copy of the project. This kit
checks, with real processes, that files reach the hub from such a run and the
other way round: a task's input file gets to the agent on the device, and the
files the agent attaches get back to the hub whole, even one far bigger than
the 384 KiB a run's result can carry.

[`run.sh`](run.sh) sets everything up and tears it down again:

- a hub on `127.0.0.1:18513` with its own `HOME`, `CLOOP_HOME`, directory, API
  token and `ui.external_url`, from the cloop under test (`BIN`, a static
  build). The URL is where the run sends its files and fetches its input files;
- the project's origin, a bare repository served over TLS by
  [`../projectmove/forge.go`](../projectmove/forge.go) on `127.0.0.1:18514`;
- a second agent, enrolled with the hub, running the cloop under test with the
  stand-in [`claude`](claude) first on its `PATH`. With `DEVICE=local` (the
  default) it runs on this host under the work directory; with `DEVICE=<ssh
  host>` it runs on that machine under `/tmp/cloop-attachments-rig` and reaches
  the hub and the forge over `ssh -R`;
- a placeholder Claude credential granted to the project, because the hub
  refuses to dispatch a claudecode run to a device without one. The stand-in
  ignores it, and the hub has to scrub it from every file.

```bash
CGO_ENABLED=0 go build -o /tmp/cloop-static .
cd /tmp && BIN=/tmp/cloop-static scripts/e2e/attachments/run.sh              # this host
cd /tmp && BIN=/tmp/cloop-static DEVICE=sgx scripts/e2e/attachments/run.sh   # a device
```

Run it from a directory outside the repository: a cloop started in the
repository's root opens and migrates the hub database there.

## The checks

The task gets an input file, `spec.txt`, uploaded the way the dashboard does.
The stand-in copies it to `echo.txt` and attaches it with `plots/big.bin`
(2 MiB of deterministic pseudo-random bytes), `report.md` (which quotes the
credential the run was leased) and `small.txt`.

| Check | Expected |
| --- | --- |
| `spec.txt` after the upload | an input file of the task |
| `plots/big.bin` | on the hub, and served byte for byte |
| `report.md` | on the hub, without the leased credential |
| `echo.txt` | the same bytes as `spec.txt`: the agent on the device worked from the input file |
| the task's results | four, each attached once |
| the hub's audit trail | four `run.result_upload` rows with outcome `attached`, and the `run.input_fetch` row |
| the project's journal | the merge counts the files the run sent while it ran |
| `.cloop/attachments/held` on the hub | empty once the run is merged |

`results.log` in the work directory has every check and the table of the
task's attachments.

## Last run

2026-11-22, Task 20513, on this host (`DEVICE=local`; the sgx device was not
reachable that day). The cloop built from the working tree before it was
committed passed every check. The same rig with the build before the change
(`git archive HEAD`) showed the gap the change closes:

```text
    plots/big.bin    result   2097152 left in the executor's workspace: at 2.0 MiB it did not fit in what is left of the 384.0 KiB of attachments a run's result carries
23:03:26 FAIL plots/big.bin (2 MiB, over the 384 KiB a result carries) is on the hub
23:03:26 FAIL the hub serves plots/big.bin byte for byte
```

Its input file, small files and scrubbing already worked.
