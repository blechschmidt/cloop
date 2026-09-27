# Live check: the git proxy from inside a device's sandbox

`pkg/gitproxy`'s tests prove the proxy against a forge on loopback. This kit
proves the whole path on real hardware: a hub with `executors.git_proxy` on, an
enrolled device, a sandbox on that device holding a guarded GitHub lease, the
sandbox's own `git`, and GitHub itself. It checks the three restrictions a grant
can carry — **branches**, **read-only** and **repositories** — plus the property
they all rest on: the sandbox never holds a GitHub token.

It was written for, and first run in, Task 20346 against the sgx device.

## Why a stand-in harness

The workload is `cloop run` with the ordinary `claudecode` provider, so
dispatch, the project seed, the lease, the harness environment and the result
all take their production paths. Only the `claude` binary is replaced: [`claude`](claude)
takes the prompt on stdin like the real CLI, runs the probe carried in the task
description, prints its report and signals `TASK_DONE`. A run is deterministic,
needs no Claude login in the sandbox, and cannot "helpfully" work around a
refusal it was meant to report.

## The pieces

| File | What it is |
| --- | --- |
| `probe.sh` | the checks, run inside the sandbox; one `RESULT` line each |
| `claude` | the stand-in harness that runs the probe |
| `Dockerfile` | the sandbox image: harness image + the cloop under test + the stand-in |
| `mktask.sh` | adds a probe task to a project over the hub API |

## The rig

1. **A hub with the proxy on**, reachable by the sandbox — not only by the
   device. `advertise_url` is what the sandbox's `git` dials, so it needs an
   address routable from inside the container and a certificate the image
   trusts; a public name with a public certificate needs nothing else:

   ```yaml
   executors:
     git_proxy:
       enabled: true
       listen_addr: "0.0.0.0:18346"
       advertise_url: "https://hub.example.com:18346"
       cert_file: /etc/letsencrypt/live/hub.example.com/fullchain.pem
       key_file: /etc/letsencrypt/live/hub.example.com/privkey.pem
   ```

   A test hub beside a production one: give it its own `HOME`, `CLOOP_HOME`,
   workdir and port, protect its API with a token, and reach the device's agent
   over `ssh -R` so the agent dials loopback.

2. **A device** enrolled against that hub, and on it the image:
   `docker build -t cloop-harness:gitproxy-probe .` (see the `Dockerfile` header).

3. **Sandboxes.** A virtual executor per shape you want covered — `runc`,
   `runsc`, one with a firewall — all with image `cloop-harness:gitproxy-probe`.
   **Give each a network.** A virtual executor with neither a firewall nor
   `network` runs with `--network=none`, and every clone then fails with
   `Could not resolve host`. Either `"network": "bridge"`, or a firewall whose
   only allow is the proxy:
   `{"allow_cidrs": ["<hub-ip>/32"], "allow_ports": [18346], "resolvers": ["1.1.1.1"]}`
   (the agent needs `--packet-filter` for that one). Host mode needs the stand-in
   and the cloop under test first on the agent's `PATH`.

4. **A GitHub credential and two repositories it can reach.** The second is
   what the per-repository checks are refused. A GitHub App secret exercises the
   App path; a `github_pat` secret holding a token that reaches *both* repositories
   exercises the case where the proxy is the only thing narrowing it.

5. **One project per scenario**, bound to an executor, with repository access
   assigned through `POST /api/projects/{idx}/repositories` — the panel's path:

   | scenario | access | branches |
   | --- | --- | --- |
   | `branch` | write | `cloop/e2e-allowed-*` |
   | `readonly` | read | — |
   | `pat` | write (on the `github_pat` secret) | — |
   | `ws` | write, `cloop/e2e-ws-*`; the project directory is a checkout of the granted repository, so the device provisions it through the proxy | |

## Running it

```bash
export CLOOP_HUB=http://127.0.0.1:18347 CLOOP_HUB_TOKEN=...
./mktask.sh 1 branch   acme/granted acme/other
./mktask.sh 2 readonly acme/granted acme/other VICTIM=cloop/e2e-victim-1   # an existing scratch branch
./mktask.sh 3 pat      acme/granted acme/other
./mktask.sh 5 ws       acme/granted acme/other
curl -X POST -H "Authorization: Bearer $CLOOP_HUB_TOKEN" "$CLOOP_HUB/api/run?project_idx=1"
```

The report is the task's step output (`GET /api/steps?project_idx=N&limit=1`).
Every line is `RESULT <id> PASS|FAIL <detail>`, then `SUMMARY`.

## What each result means

| id | passes when |
| --- | --- |
| T1 | no GitHub-issued token (`ghp_`, `ghs_`, … in both the classic and the long `ghs_<id>_<…>.<…>.<…>` form) is in the environment, the lease directory or the project state |
| T2 | the lease's session token, presented to github.com directly, is refused — or github.com is unreachable |
| T3 | without the lease's git config the sandbox has no credential for the private repository |
| P1 | `git clone https://github.com/<repo>` works — rewritten to the proxy by the lease |
| P2–P4 | `ls-remote`, `clone` and `push` of the other repository are refused **by the proxy** |
| P5.n | encoded, `.git.git`, upper-case and `..` spellings of the other repository are refused |
| B1 / B8 | a push, then a fast-forward, to a branch inside the grant's list land on GitHub |
| B2 | a branch inside the hub's `refs/heads/cloop/**` but outside the grant's list is refused, naming the grant's list |
| B3 / B4 / B7 | `main`, a branch outside the hub's allowlist, and a tag are refused |
| B5 | deleting the allowed branch is refused |
| B6 | a push carrying an allowed ref and `main` is refused as a whole |
| R1–R5 | fetch works; pushes and a delete are refused at the advertisement; the lease says read-only |
| W1–W3 | on a broad `github_pat`: the hub's allowlist holds, and the other repository stays refused |
| WS1–WS5 | the provisioned workspace is the granted repository at `main`, its origin is the proxy, it holds no credential, and pushes from it follow the grant |

A refusal counts only if the proxy made it (its `cloop git proxy` body or a
`remote rejected` report), and every push check re-reads the ref afterwards —
so a network failure or a push git never sent cannot pass as a refusal.

## On the hub

```bash
cloop audit-log list --entity gitproxy --since 1h
```

Every run should show a `session_minted` and a `session_closed` per session,
every `fetch`, `push_allowed`, `push_denied` and `rejected` naming the repository
the request addressed, and no `rejected … no basic credential` rows: git's own
401 challenge is counted in `cloop_gitproxy_anonymous_requests_total` instead.

## Cleaning up

The proxy never deletes a ref, so the allowed pushes stay on GitHub. Delete
them with a token the hub holds, outside the proxy
(`DELETE /repos/<repo>/git/refs/heads/<branch>`), and revoke any installation
token minted for the check.
