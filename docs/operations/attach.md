# Live sandbox attach

Attach gives you a shell inside a sandbox while its task is running, from the
dashboard or with `cloop task attach`. By default, nobody below the `admin`
role can use it.

Attach is the only operation in cloop that reaches *through* the isolation
boundary around a sandbox. This page describes how cloop makes sure every use
is explicitly granted, limited in scope, and recorded.

## Why it exists

Without attach, when a task seems stuck you can only read its artifact or abort
the run. Neither tells you what the task is doing inside the sandbox.

Attach is for problems the transcript can't show, such as:

- a harness blocked on a DNS lookup that the egress policy drops without any
  response;
- a workspace provisioned into the wrong directory;
- a `git push` failing because the credential helper the lease installed is
  not on `PATH`.

In each case the transcript shows a process that has stopped producing output,
while one `ps`, `env` or `ls` in the sandbox shows the reason.

## Who may use it

Two permissions control attach, and no role below `admin` has either of them by
default.

| Permission | Grants |
| --- | --- |
| `sandbox.attach` | Open a **read-only** session: you see the sandbox's output but can't type. |
| `sandbox.attach.write` | Also send input. Requires `sandbox.attach` too, since you can't type into a terminal you may not open. |

They are separate permissions, not part of `project.read`, for two reasons:

- `project.read` gives you the transcript the harness chose to write. Attach
  gives you the sandbox's filesystem, process table and environment, and
  whatever it holds at that moment. Including attach in `project.read` would
  have given that access to every viewer on the hub.
- Watching and intervening are different. Anything typed into a writable
  session runs as the workload, with the workload's credentials, inside a run
  whose output will be attributed to an AI agent. The audit row is the only
  record that a person was involved as well.

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

A caller without `sandbox.attach` gets a 404, as if the route did not exist,
not a 403. Every other read denial works the same way, so a missing permission
reveals nothing about which tasks are running.

## What cannot be attached to

**Tasks running as host processes.** There is no sandbox to enter, so a
"sandbox shell" would be a shell on the control plane. `executor.AttachTarget`
refuses before any driver is involved, and the error gives the reason:

```
attach refused: workload runs on the host, not in a sandbox
(executor "localprocess", kind "localprocess"; executors.allow_host_process is false)
```

On a hub where `executors.allow_host_process` is `true`, attach is still
refused, because the task runs on the host, but the message doesn't blame a
policy that isn't set. See [the security model](../security/model.md) for how
the code makes host execution and sandbox attach mutually exclusive.

**Tasks that have finished, or have not started a sandbox yet.** cloop looks
the task up in the control plane's record of what it dispatched where
(`executor_sessions`), not in the executor recorded on the task. That record
says where a task *ran*, which is right for provenance but wrong here: it
outlives the run, and attaching to a handle that has already exited would fail
in confusing ways.

## Backends

All three isolating drivers support attach, with small differences:

| Driver | How | Terminal |
| --- | --- | --- |
| Container | `docker`/`podman exec` against the live handle | Full pty |
| Kubernetes | `pods/exec` over the `v4.channel.k8s.io` WebSocket | Full pty, with window-size reporting |
| Remote agent | A frame type multiplexed onto the session the device already holds open | Full pty on Linux devices; pipes elsewhere |
| localprocess | Not applicable | Always refused |

The Kubernetes driver needs the `pods/exec` subresource on the namespace, which
a kubeconfig that can only create Pods doesn't have. The error says so, instead
of reporting a bare handshake failure:

```
the kubeconfig for this project may not exec into pods
(needs the pods/exec subresource on cloop-sandboxes)
```

Remote agents need protocol **v7 or newer**. An older device still runs work
but can't be attached to. The hub refuses the session instead of sending frames
the agent would log as unexpected and drop. The error names the protocol the
device speaks and how to move it forward from this hub. The Upgrade button
installs published releases only, so on a hub running an unreleased build the
fix is a binary built from the hub's commit, installed on the device. See
[Moving a device forward](../architecture/executors.md#moving-a-device-forward-which-remedy-works).

## Read-only means read-only in the sandbox

A read-only session has no input channel at all; it is not a channel the hub
chooses to ignore. The process started in the sandbox has no stdin:

- the container driver omits `-i`, so the runtime opens no input descriptor;
- the Kubernetes driver omits `stdin=true` from the exec request;
- the agent passes `/dev/null` and drops any input frame that arrives anyway.

The last one matters most, because the machine that runs the command enforces
it, so a compromised or buggy hub can't get a writable terminal. `tests/security`
and the container driver's `TestAttach_ReadOnlySessionHasNoStdinInTheSandbox`
both check this.

## Credentials in the transcript

Terminal output is scrubbed with the same redaction set the log stream uses.
cloop takes it from the handle's log bus instead of building a new one, so a
credential filtered out of the live log can't reappear when someone opens a
terminal on the same workload. Scrubbing works across reads: a token split
across two reads is held back and matched, because a terminal would put it back
together on screen.

For remote agents, the scrubbing happens on the device, before the bytes leave
it.

This reduces the risk but doesn't remove it. The lease broker avoids exporting
a bare token wherever it can, and the redaction set covers the values the broker
declared sensitive. But a terminal can read anything, and a credential nobody
declared is a credential nobody scrubs. That is why the permission is
admin-only by default and not something a viewer holds.

## The audit trail

Every session writes to the tamper-evident trail. You can see it in the Audit
panel and export it to a SIEM like every other event:

| Event | When |
| --- | --- |
| `sandbox.attach.open` | Before the session opens |
| `sandbox.attach.denied` | A driver refused after the permission check passed |
| `sandbox.attach.close` | The session ended, with the reason |

Each row records the acting identity, a session ID that links open with close,
the executor and handle, the task, the command as the caller wrote it, and
whether the session could type.

`open` is written *before* the session starts. An audit event written only on
close could be erased by a crash, or by a caller who causes one.

Keystrokes are not recorded. A full transcript would be a second, unscrubbed
copy of everything the sandbox holds, kept on the control plane outside the
lease that governs the original, and readable by anyone with `audit.read`. The
audit event records who did what. A transcript would be a way to get data out.

## When access ends

An open terminal is re-authorized every 30 seconds for as long as it stays
open. If `sandbox.attach` is withdrawn (by a deny binding, a changed role or a
removed project membership), the terminal closes at the next check.

It also ends when the credential that opened it ends. A revoked, signed-out,
expired or idle session, or a revoked or expired API token, closes the terminal
with a `closed` frame giving the reason and a `1008` close naming
`session_ended` or `token_revoked`. The `sandbox.attach.close` event records
it. If the hub hears of a revocation (from the Sessions or Tokens panel,
another hub member, or `cloop
hub session revoke`, `token revoke` or `user offboard`), the terminal closes at
once. Any other ending takes effect at the next check. Each check uses the permissions the terminal's own credential
has at that moment, so a terminal whose session has ended is never
re-authorized as anybody else, including the static token.

## Limits

| Limit | Default | Where |
| --- | --- | --- |
| Concurrent sessions per executor | 4 | Hub policy (`executor.AttachLimiter`) |
| Sessions per agent connection | 16 | Structural backstop in the frame router |
| Sessions per edge device | 8 | The device protecting itself |
| Idle timeout | 30 min | Hub |
| Inbound frame | 64 KiB | Hub |

The per-executor limit is small because each session is a live exec process
holding a pty inside the sandbox, and it runs on the *workload's* machine. A
debugging tool that could be opened forty times on a struggling sandbox could
overload the sandbox it is meant to help diagnose.

When a device's connection drops, every terminal on it ends. Attach sessions
can't be resumed: the process on the far side ends with the connection, and
reconnecting you to a different shell would be worse than telling you the
session ended. A shell left running would also be a process holding the
project's credentials with nobody accountable for it, which is what the audit
trail exists to prevent.

## Using it

### From the CLI

```bash
# Read-only shell in task 41's sandbox
cloop task attach 41

# One command, then exit
cloop task attach 41 -- ps aux

# Interactive (needs sandbox.attach.write)
cloop task attach 41 --write

# Against a hub with single sign-on, signed in with `cloop login` first
cloop login https://hub.example.com:8888
cloop task attach 41

# Against a remote hub, with an API token
cloop task attach 41 --hub https://hub.example.com:8888 --token "$CLOOP_API_TOKEN"
```

cloop chooses the hub in this order:

1. `--hub`;
2. `$CLOOP_HUB_URL`;
3. the default hub [`cloop login`](../getting-started/terminal.md) recorded.
   This need not be the hub on this machine, so cloop names it on stderr before
   you type anything;
4. `http://127.0.0.1:8080`.

It chooses the credential in this order:

1. `--token`;
2. the session `cloop login` stored for that hub. This is your own session,
   with your permissions, and revoking it ends the terminal;
3. `$CLOOP_API_TOKEN`, where it is that hub's token. Next to `$CLOOP_HUB_URL`
   it is that hub's token and no other's. On its own it is the local hub's
   token when nothing names a hub, and otherwise it is used only for a hub with
   no stored session.

On a multi-project hub, pass `--project-idx`.

With `--write`, your local terminal is switched to raw mode, so keystrokes reach
the sandbox one at a time and the remote shell's own echo is the only echo.
Window resizes are forwarded.

> `cloop task attach` is **not** `cloop task exec`. That command runs something
> on *this* machine with the task's environment variables. `cloop task attach`
> runs it inside the container, pod or device where the task is running.

### From the dashboard

Open a task's details and press **Attach**. If the task has no sandbox you can
attach to, the button is disabled and its tooltip says why.

The browser terminal is a `<pre>` with line-based input, not a terminal
emulator: ANSI sequences are stripped and the buffer it keeps is capped. It is
meant for convenience. For a full session with line editing, full-screen
programs and job control, use `cloop task attach --write`.

## Troubleshooting

| Symptom | Cause |
| --- | --- |
| Button disabled, "not running on any executor" | The task finished, or has not been dispatched yet. |
| 403, "workload runs on the host" | The task ran as a host process. Bind the project to a container, Kubernetes or remote executor. |
| 501, "attach not supported by this executor" | An isolating driver that can't attach. In practice, a remote agent older than protocol v7. |
| 429 | The per-executor limit is reached. `sessions_open` and `sessions_max` are in the `/attach/info` response. |
| 404 on a task you can see | You have `project.read` but not `sandbox.attach`. Read denials hide whether the resource exists. |
| Terminal opens but typing does nothing | You have `sandbox.attach` but not `sandbox.attach.write`. The banner says which kind of session you got. |
| No prompt, no echo, commands still work | The pty could not be allocated (a non-Linux device, or `/dev/pts` not mounted), so the session fell back to pipes instead of failing. |

## See also

- [Security model](../security/model.md): the isolation guarantees attach
  reaches through, and why host execution rules it out
- [Executors](../architecture/executors.md): the driver abstraction that the
  `Attacher` interface extends
- [Operator runbook](runbook.md): audit chain verification and SIEM export
