# Live check: a device installs copilot on request, then runs a copilot task

`pkg/executor/agent`'s tests prove the installer table, the fetch rules and the
path pin against local servers, and `pkg/executor/remote`'s prove the hub's
side of the frame. This kit proves the whole path on a real device (Task
20450): a test hub, an agent on the device with no `copilot` anywhere it looks,
a `copilot` project bound to it, and the hub's `executors.auto_install_harness`
switch both ways.

The model is [`model.py`](model.py), on the device's loopback: the Copilot CLI's
bring-your-own-key mode (`COPILOT_PROVIDER_BASE_URL` with `COPILOT_OFFLINE`)
against an OpenAI-compatible stand-in that asks for one `bash` tool call —
write `copilot-hello.txt` and show it — and then signs off with `TASK_DONE`. No
GitHub account and no Copilot seat; the CLI, its tool loop and the agent's
install path are all real.

## The checks

[`run.sh`](run.sh) prints one `PASS` or `FAIL` line per row and exits non-zero
on any failure.

| step | expected |
| --- | --- |
| `auto_install_harness: false`, start the copilot project | **409**, naming `copilot` and `ghcr.io/blechschmidt/cloop-harness-copilot` |
| … and the device | asked nothing: no `harness install` line in its log |
| `auto_install_harness: true` (read on each dispatch, no restart), start it again | the task is **done** on the hub |
| … and the device | fetched `https://gh.io/copilot-install` (301 to `raw.githubusercontent.com/github/copilot-cli/…`), installed the CLI into the agent user's `~/.local/bin/copilot` |
| the installed binary | `copilot --version` says `GitHub Copilot CLI` |
| the model | received the `bash` tool's result — the file's contents — from the CLI on the device |
| `GET /api/executors` | the device's inventory lists `copilot` |

## Running it

From the hub's host, with `ssh <device>` working as root:

```bash
scripts/e2e/copilot-device/run.sh              # DEVICE=sgx by default
DEVICE=edge-2 PORT=18460 STUB_PORT=18461 scripts/e2e/copilot-device/run.sh
KEEP=1 scripts/e2e/copilot-device/run.sh       # leave both trees for a look
```

It builds the cloop under test statically (or takes `BIN`), and everything it
starts is its own and goes on exit:

- **the hub**: `cloop ui` on this host, bound to `127.0.0.1:$PORT`, with its own
  `HOME`, workdir, `CLOOP_SECRET_KEY` and API token, and an environment built
  from nothing — a hub's child process inherits `CLOOP_SECRET_KEY` and, on an
  SSO hub's host, `CLOOP_COPILOT_HOME`, either of which would make it test
  something else;
- **the tunnel**: `ssh -N -R $PORT:127.0.0.1:$PORT`, so the agent dials its own
  loopback;
- **on the device**, under `/tmp/cloop-copilot-device-$PORT`: the cloop under
  test, the stand-in model, and a second agent — run as the production agent's
  user (`AGENT_USER`, default `cloop-executor`) with a `HOME` of its own, which
  is where the installer puts the CLI, and with the cloop under test first on
  its `PATH`, because the hub dispatches the bare name `cloop run` and the
  device's own `/usr/local/bin/cloop` is a release.

The production agent is not touched. Processes on the device are stopped by the
PIDs the script recorded, never by a pattern: a pattern matches the ssh shell
that runs it, and the production agent runs as the same user.

## First run (2026-10-27, sgx)

All checks passed against sgx — an Alibaba Cloud VM in Jakarta, the device the
claude installer's mirror was added for because the claude.ai website answers
it with a Cloudflare challenge. `gh.io` does not: the redirect, the script and
the release download all reach it, so the copilot entry has no mirror. The
install took about 10 s and put CLI 1.0.104 in the agent's `~/.local/bin`; the
task's run took 3 s.

The run found one defect, fixed with it: the Fleet panel's inventory read the
device's hello, so a device that had just installed copilot kept a card saying
it had none until its agent reconnected.
