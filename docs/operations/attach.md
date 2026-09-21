# Live sandbox attach

Getting a shell inside a sandbox that is running right now — from the dashboard,
from `cloop task attach`, or not at all, which is the default.

Attach is the one operation in cloop that reaches *through* the isolation
boundary the rest of the product exists to maintain. Everything below is about
making that reach deliberate, narrow, and attributable.

## Why it exists

Before this, an operator watching a task hang had exactly two tools: tail the
artifact, or abort the run. Neither answers the question that matters — *what is
it actually doing in there* — and for a product whose premise is that work runs
somewhere else, "somewhere else" had no door.

The failures this is for are the ones the transcript cannot describe. A harness
blocked on a DNS lookup that the egress policy is silently dropping. A workspace
that was provisioned into the wrong directory. A `git push` failing because the
credential helper the lease installed is not on `PATH`. In each case the
transcript shows a process that has stopped saying anything, and the sandbox
shows the reason in one `ps`, one `env`, one `ls`.

## Who may use it

Two new permissions, and **no role below `admin` holds either by default.**

| Permission | Grants |
| --- | --- |
| `sandbox.attach` | Open a **read-only** session: you see the sandbox's output, you cannot type. |
| `sandbox.attach.write` | Additionally send input. Requires `sandbox.attach` as well — there is no typing into a terminal you may not open. |

They are separate permissions, not a widening of `project.read`, and that
distinction is load-bearing:

- `project.read` delivers the transcript the harness chose to emit. Attach
  delivers the sandbox's filesystem, its process table, its environment and
  whatever it happens to be holding at that instant. Folding attach into
  `project.read` would have silently promoted every viewer on the hub.
- Observing and intervening are different acts. Anything typed into a writable
  session runs **as the workload, with the workload's credentials**, inside a run
  whose output is about to be attributed to an AI agent. The audit row is the
  only artefact that will ever say two authors were involved.

Grant them explicitly:

```yaml
authz:
  bindings:
    # An on-call engineer who may look inside a struggling sandbox,
    # but may not administer the fleet.
    - claim: group
      value: sre-oncall
      role: operator
      permissions: [sandbox.attach]

    # A smaller group that may also intervene.
    - claim: group
      value: sre-leads
      role: operator
      permissions: [sandbox.attach, sandbox.attach.write]
```

A caller without `sandbox.attach` is told the route does not exist (404), not
that it is forbidden — the same withholding every other read denial uses, so the
absence of the permission leaks nothing about which tasks are running.

## What cannot be attached to

**Tasks running as host processes.** There is no sandbox to enter; the "sandbox
shell" would be a shell on the control plane. The refusal happens in
`executor.AttachTarget`, before any driver is consulted, and it names the reason:

```
attach refused: workload runs on the host, not in a sandbox
(executor "localprocess", kind "localprocess"; executors.allow_host_process is false)
```

On a hub where `executors.allow_host_process` is `true` the refusal still
happens — host execution is what costs you the shell — but the message says so
without blaming a policy that is not set. See
[the security model](../security/model.md) for why host execution and sandbox
attach are mutually exclusive by construction rather than by convention.

**Tasks that have finished, or have not started a sandbox yet.** The lookup is
against the control plane's record of what it dispatched where
(`executor_sessions`), not against the executor stamped on the task. The stamp
says where a task *ran*, which is right for provenance and wrong here: it
survives the run, and attaching to a handle that already exited would at best
fail confusingly.

## Backends

All three isolating drivers support it. What you get differs slightly:

| Driver | How | Terminal |
| --- | --- | --- |
| Container | `docker`/`podman exec` against the live handle | Full pty |
| Kubernetes | `pods/exec` over the `v4.channel.k8s.io` WebSocket | Full pty, with window-size reporting |
| Remote agent | A new frame type multiplexed onto the session the device already holds open | Full pty on Linux devices; pipes elsewhere |
| localprocess | — | Refused, always |

The Kubernetes path needs the **`pods/exec` subresource** on the namespace, which
a kubeconfig that can only create Pods does not have. The failure is reported
with that remediation rather than as a bare handshake error:

```
the kubeconfig for this project may not exec into pods
(needs the pods/exec subresource on cloop-sandboxes)
```

Remote agents need protocol **v7 or newer**. An older device runs work perfectly
well and simply cannot be entered; the hub refuses the session rather than
sending frames the agent would log as unexpected and drop. To upgrade it,
press Upgrade on the device's row in the Executors panel, or run `sudo cloop executor agent install --upgrade` on it.

## Read-only means read-only in the sandbox

A read-only session does not get an input channel that the hub then declines to
use. The exec'd process has **no stdin at all**:

- the container driver omits `-i`, so the runtime opens no input descriptor;
- the Kubernetes driver omits `stdin=true` from the exec request;
- the agent passes `/dev/null` and drops any input frame that arrives anyway.

That last one matters most: it is the refusal on the machine where the command
runs, so a hub that was compromised or simply buggy cannot talk its way into a
writable terminal. `tests/security` and the container driver's
`TestAttach_ReadOnlySessionHasNoStdinInTheSandbox` both assert it.

## Credentials in the transcript

Output is scrubbed through **the same redaction set the log stream uses** — taken
from the handle's log bus rather than rebuilt, so a credential filtered out of
the live log cannot reappear the moment someone opens a terminal on the same
workload. Scrubbing survives read boundaries: a token split across two reads is
held back and matched, because a terminal reassembles it on screen perfectly.

For remote agents the scrub happens **on the device, before the bytes leave it**.

This is a real mitigation, not a guarantee. The lease broker deliberately never
exports a bare token where it can avoid it, and the redaction set covers the
values the broker declared sensitive — but a terminal is a general-purpose
reader, and a credential nobody declared is a credential nobody scrubs. That is
precisely why the permission is admin-only by default rather than something a
viewer holds.

## The audit trail

Every session writes to the tamper-evident trail, visible in the Audit panel and
exportable to a SIEM like every other event:

| Event | When |
| --- | --- |
| `sandbox.attach.open` | Before the session opens |
| `sandbox.attach.denied` | A driver refused after the permission check passed |
| `sandbox.attach.close` | The session ended, with the reason |

Each row carries the acting identity, the session ID correlating open with close,
the executor and handle, the task, **the command as the caller wrote it**, and
whether the session could type.

`open` is written *before* the session starts, not after it ends. An audit
written on close is an audit that a crash — or a caller who forces one — erases.

**Keystrokes are not recorded.** A full transcript would be a second, unscrubbed
copy of everything the sandbox holds, living on the control plane, outside the
lease that governs the original, and readable by anyone with `audit.read`. The
event is the accountability; the transcript would be an exfiltration route
wearing accountability's clothes.

## Limits

| Limit | Default | Where |
| --- | --- | --- |
| Concurrent sessions per executor | 4 | Hub policy (`executor.AttachLimiter`) |
| Sessions per agent connection | 16 | Structural backstop in the frame router |
| Sessions per edge device | 8 | The device protecting itself |
| Idle timeout | 30 min | Hub |
| Inbound frame | 64 KiB | Hub |

The per-executor ceiling is small deliberately: each session is a live exec
process holding a pty inside the sandbox, so the resource being protected is the
*workload's* machine. A debugging tool that can be pointed at a struggling
sandbox forty times over is a denial-of-service primitive against the thing it
is meant to diagnose.

When the device's link drops, every terminal on it ends. An attach session is not
resumable — the process on the far side is gone with the connection, and
reconnecting an operator into a different shell would be worse than telling them
it ended. A shell left running would also be an unattributed process holding the
project's credentials, which is exactly what the audit trail exists to rule out.

## Using it

### From the CLI

```bash
# Read-only shell in task 41's sandbox
cloop task attach 41

# One command, then exit
cloop task attach 41 -- ps aux

# Interactive (needs sandbox.attach.write)
cloop task attach 41 --write

# Against a remote hub
cloop task attach 41 --hub https://hub.example.com:8888 --token "$CLOOP_API_TOKEN"
```

The hub URL defaults to `http://127.0.0.1:8080` or `$CLOOP_HUB_URL`; the token
also reads `$CLOOP_API_TOKEN`. On a multi-project hub, pass `--project-idx`.

With `--write` the local terminal is put into raw mode, so keystrokes reach the
sandbox one at a time and the remote shell's own echo is the only echo. Window
resizes are forwarded.

> `cloop task attach` is **not** `cloop task exec`. That command runs something on
> *this* machine with the task's environment variables. This one runs it inside
> the container, pod or device the task is actually executing in.

### From the dashboard

Open a task's details and press **Attach**. The button is disabled with the
reason in its tooltip when the task has no attachable sandbox, so you learn why
before the click rather than after it.

The browser terminal is a `<pre>` with a line-oriented input, not a terminal
emulator: ANSI sequences are stripped and the retained buffer is capped. It is
deliberately the convenience path. For a full-fidelity session — line editing,
full-screen programs, job control — use `cloop task attach --write`.

## Troubleshooting

| Symptom | Cause |
| --- | --- |
| Button disabled, "not running on any executor" | The task finished, or has not been dispatched yet. |
| 403, "workload runs on the host" | The task ran as a host process. Bind the project to a container, Kubernetes or remote executor. |
| 501, "attach not supported by this executor" | An isolating driver without the capability — in practice, a remote agent older than protocol v7. |
| 429 | The per-executor ceiling is reached. `sessions_open` and `sessions_max` are in the `/attach/info` response. |
| 404 on a task you can see | You hold `project.read` but not `sandbox.attach`. Read denials withhold existence. |
| Terminal opens but typing does nothing | You hold `sandbox.attach` but not `sandbox.attach.write`. The banner says which session you got. |
| No prompt, no echo, commands still work | The pty could not be allocated — a non-Linux device, or `/dev/pts` not mounted. The session degraded to pipes rather than refusing. |

## See also

- [Security model](../security/model.md) — the isolation guarantees attach
  reaches through, and why host execution forecloses it
- [Executors](../architecture/executors.md) — the driver abstraction the
  `Attacher` interface extends
- [Operator runbook](runbook.md) — audit chain verification and SIEM export
