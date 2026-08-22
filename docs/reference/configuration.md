# Configuration reference

Executor backends, sandbox settings, transport security and hardening keys for
`.cloop/config.yaml`.

Conceptual documentation lives elsewhere: [how executors work](../architecture/executors.md),
[what each boundary authenticates with](../security/model.md), and
[granting credentials](../guides/secrets.md). This file is the key-by-key
reference those documents refer to.

---

## Execution Backends (Executors)

An **executor** decides *where* a cloop workload actually runs. By default it is
a child process on the same host as cloop itself, with the same user, the same
filesystem, and the same network. That is fine on a laptop. It is not fine for a
hosted deployment where the agent executes model-authored code on someone else's
behalf.

Projects are pinned to an executor. A project bound to an executor that is not
available **fails** rather than silently falling back to host execution — an
isolation boundary you opted into is never downgraded because the backend
happened to be unreachable.

| Kind | Isolation | Where it runs | Notes |
|------|-----------|---------------|-------|
| `localprocess` | none | this host | Default. Zero-config, no sandbox. |
| `container` | container | this host | Docker/Podman sandbox. Opt-in via config. |
| `remote` | remote | an enrolled device | Edge box that dialled out to the control plane. |

```bash
cloop executor list              # what is registered, and what it isolates
cloop executor ls                # fleet health: state, in-flight work, last seen
cloop executor test <id>         # preflight + run `cloop version` inside it
cloop executor reap <id>         # remove containers left by a killed control plane
cloop executor cordon <id>       # stop new placement; in-flight work continues
cloop executor uncordon <id>     # back in rotation, at the health its probes justify
cloop executor drain <id>        # stop placement, wait for in-flight to reach zero
cloop executor enroll            # mint a token for a remote device
cloop executor agent --server …  # run *on* the device
cloop executor revoke <id>       # kill a leaked token or a decommissioned device
```

### The Executors panel

The web dashboard has a global **Executors** tab: one card per backend with a
live status dot, a kind badge (host / container / remote), capability chips,
current load, and enroll/revoke actions. Status changes arrive over the same
WebSocket the rest of the dashboard uses — nothing polls.

Each project's execution target is a one-click setting: the **Executor** card on
the project Overview page, next to the provider card. Changing it takes effect
on the next run; work already in flight stays on the executor that started it.

The tab's banner always states the effective host-execution mode, so "can this
server still fork a harness next to itself" is never something you have to infer
from a config file.

### Container sandbox

Enable it in `.cloop/config.yaml`:

```yaml
executors:
  container:
    enabled: true
    runtime: podman          # or docker; empty auto-detects (podman preferred)
    image: ghcr.io/blechschmidt/cloop-harness:latest
    cpus: 2                  # core allowance per workload
    memory: 2g               # 512m / 2g / 1024k; a bare integer means MB
    pids_limit: 1024         # process cap; -1 disables
    network: none            # none (default) | bridge | <named network>
    extra_args: []           # additional runtime flags, --flag=value form only
    selinux_label: ""        # "z" or "Z" — required when SELinux is enforcing
```

or with `cloop config set executors.container.<key> <value>`.

Every container is started with:

- **only the project directory** bind-mounted, at the fixed path `/workspace`.
  Nothing else of the host is visible.
- a **non-root UID** taken from the project directory's owner, so files the
  workload creates are owned correctly on the host and an escape lands on an
  unprivileged user. Under rootless podman the same is achieved with
  `--userns=keep-id`.
- **`--network=none`** by default. Egress is opt-in, per executor.
- **all Linux capabilities dropped** and `no-new-privileges` set, so a setuid
  binary in the image cannot undo the UID choice.
- **`--cpus` / `--memory` / `--pids-limit`**, with swap pinned to the memory
  ceiling so paging cannot evade it.
- a deterministic name, `cloop-<project>-<runID>`, so orphans stay reapable.

**Secrets** (provider API keys, brokered credentials) are injected as
environment at start using the bare `--env NAME` form: the runtime reads each
value from its own environment, so no secret ever appears in the host's process
table. Nothing is baked into an image and nothing is written to the mounted
workdir.

Unlike host execution, a container workload does **not** inherit the control
plane's environment. Forwarding it would hand the sandbox every credential the
server holds, so variables are passed explicitly or not at all.

### What the container sandbox does not do

- **It does not filter egress itself.** Anything other than `network: none`
  grants unrestricted outbound access unless the named network carries its own
  policy. `cloop executor test` says so explicitly rather than implying a
  guarantee. The supported way to give a sandbox *scoped* network access is to
  leave it on `network: none` and grant it egress through the broker — see
  [Scoped network egress](#scoped-network-egress) below.
- **It does not pull images.** Runs use `--pull=never` so a cold image cache
  fails immediately with an actionable error instead of turning a UI click into
  a multi-minute hang. Preflight tells you what to pull.
- **It does not enforce disk quotas.** A `DiskMB` request is refused rather
  than accepted and ignored, because writable-layer quotas only work on a
  minority of storage-driver configurations.

`extra_args` is validated: flags that would dismantle the sandbox
(`--privileged`, `--cap-add`, `--volume`, `--network`, `--user`, `--entrypoint`,
`--env`, …) are rejected, and every entry must be a flag in `--flag=value` form
so a bare value cannot be consumed as the image reference.

### Sandbox image contract

`executors.container.image` must provide:

- the cloop binary at `/usr/local/bin/cloop`;
- the agent harness the project's provider needs (for the default `claudecode`
  provider, the `claude` CLI on `PATH`);
- `git` and a CA bundle;
- a non-root user, since the workload runs as the project directory's owner UID.

`cloop executor test` bind-mounts the control plane's *own* binary read-only at
`/usr/local/bin/cloop`, so the smoke test is meaningful even against an image
that does not yet ship cloop.

### Per-project images: `.cloop/sandbox.yaml`

`executors.container.image` is one image for every project on the hub. A project
needing a different toolchain overrides it from its own repository, without an
operator editing this file:

```yaml
# <project>/.cloop/sandbox.yaml
image: ghcr.io/acme/rust-toolchain:1.79
resources:
  cpu: 4
  memory: 8g
```

The spec is repo-committed and therefore untrusted: it is schema-validated,
every number is clamped to the same bounds as the keys above, and it can only
make a run *more* confined than this file allows — omitting
`capabilities.network` takes the network away, and there is no field that adds
it. A spec asking for something the bound executor cannot do is refused before
the run, with the constraint named.

Full schema, the narrowing rules, per-executor support, and the digest pinning
that keeps a run reproducible: **[Per-project sandbox](sandbox.md)**.

### Remote executors (edge devices)

A remote executor runs work on a machine the control plane **cannot dial** —
an edge device behind NAT, a build box on an office network, a laptop on hotel
wifi. The connection is inverted: the device dials out and holds one multiplexed
WebSocket open, so there is no inbound port to forward, no VPN, and no firewall
rule.

Enrollment is therefore a two-step, out-of-band flow. On the control plane
(or in the Executors tab, **+ Enroll device**):

```bash
cloop executor enroll --name edge-1 --ttl 15m
```

It prints a single-use, expiring token and the exact command to paste on the
device — including the control plane's certificate pin, derived automatically
from `ui.tls.cert_file`:

```bash
cloop executor agent --server wss://cloop.example.com/api/executors/connect \
  --token <token> --pin sha256:<base64>
```

The token is **shown once** — only its hash is stored, so it cannot be
recovered. On first connect the device redeems it for a long-lived credential,
persists that 0600 at `~/.cloop/agent.json`, and reconnects with it from then
on. If a token leaks, `cloop executor revoke <id>` (or **Revoke** on the card)
kills it; if it was already redeemed, that revokes the resulting credential too,
drops the device's session, and unbinds every project that pointed at it.

That command runs the agent in the *foreground* and installs nothing. For a
device you intend to keep, install it as a supervised service instead:

```bash
CLOOP_ENROLL_BUNDLE='cloopenroll1.…' sudo -E cloop executor agent install
```

This writes a hardened systemd unit with `Restart=always` and the certificate
pin baked in, creates a dedicated non-login system user, and stores the token in
a `0600` file that the unit references by path — never on the command line,
where `systemctl show` and `ps` would print it. `--output docker` and
`--output shell` cover devices without systemd, `--dry-run` shows the unit
without writing it, and `--uninstall` reverses it idempotently. See
[Installing the agent as a service](../architecture/executors.md#installing-the-agent-as-a-service).

The Executors panel shows a one-command form of the same thing, backed by
`GET /install.sh` on the hub. That route is gated on `executor.manage` and
refuses to answer over plaintext HTTP: its body is piped into a root shell on a
device that does not yet know which control plane to trust.

#### Transport security

A token proves the *device* is authorised. It says nothing about whether the
server that answered is the control plane — so the agent verifies that
independently, before it sends anything:

- **Plaintext is refused.** `ws://` to a non-loopback host fails at startup,
  because the enrollment token and the long-lived credential would both travel
  in the clear and an agent retries forever, making one interception permanent.
  `--insecure-transport` overrides it for links already protected some other
  way, and logs a warning on every connection attempt while it is on.
- **`--pin sha256:<base64>`** requires the server's public key to be exactly the
  expected one, *in addition to* normal certificate-chain verification — never
  instead of it. cloop sets `InsecureSkipVerify` on no outbound dial, and
  `tests/security/transport_test.go` machine-checks that across the agent's
  whole import closure.
- The pin is over the **SPKI** (public key), not the certificate, so a routine
  renewal that reuses the key does not break the fleet. Rotating onto a new key
  does, deliberately — stage it by passing both pins comma-separated until every
  device has crossed over.
- The pin is stored in `~/.cloop/agent.json`, so every reconnect for the life of
  the device is pinned, not just the first one.
- **`--ca-file`** adds a PEM bundle to the trusted roots — the supported way to
  reach a private CA or a `cloop hub tls-init` certificate. There is
  deliberately no flag that disables verification instead.

Read the current pin at any time with `cloop hub pin`.

The agent endpoint deliberately sits outside the dashboard's token/OIDC auth.
Agents are not users: they carry their own scoped, individually revocable
credential rather than one that would grant full UI access. It stays behind the
rate limiter, which is what absorbs an unauthenticated flood of connect
attempts.

### Scoped network egress

A sandbox with `network: none` is safe and, on its own, not very useful: it
cannot fetch a dependency, clone a repo, or call an API. The usual escape is to
give it a real network and hope. `cloop egress` is the alternative — the
control plane lends its own connection, one destination at a time.

The sandbox keeps no route of its own. It reaches the outside world only
through an authenticated forward proxy hosted by the control plane, which
decides per connection:

```bash
cloop egress grant --to project:/srv/app \
    --hosts 'api.github.com,*.githubusercontent.com' --ports 443 \
    --max-down 500m --ttl 8h

cloop egress list                                  # who may reach what, until when
cloop egress test https://api.github.com/rate_limit  # ...and does it actually work?
cloop egress revoke egress_2f1c…                   # withdraw, closing live tunnels
```

Turn the proxy on under `executors.egress`:

```yaml
executors:
  egress:
    enabled: true
    listen_addr: "10.88.0.1:8899"                      # reachable from the sandbox
    advertise_addr: "host.containers.internal:8899"    # what goes into HTTPS_PROXY
    max_session_minutes: 15
    default_max_bytes_down: 1g
```

A grant carries hosts, CIDRs, ports, methods, byte quotas, and a TTL, targeted
with the same `--to` syntax as `cloop secret grant`. Redeeming one mints a
**single-use, per-session credential** — 256 random bits, compared in constant
time, stored only as a SHA-256 — which the workload receives as
`HTTPS_PROXY` / `HTTP_PROXY` / `NO_PROXY`. It never sees the grant itself.

What the proxy enforces:

- **Host, port, and method** are checked before a byte leaves. Methods gate
  plain HTTP only; a CONNECT tunnel's method lives inside TLS and is not
  observable (see below).
- **Resolve-once pinning.** The destination name is resolved exactly once,
  *every* returned address must pass policy, and the dial goes to the resolved
  literal. There is no second lookup for a hostile DNS server to answer
  differently, so rebinding has nowhere to put the second answer.
- **SSRF hard-block.** Loopback, RFC1918, CGNAT, link-local — which is where
  the cloud metadata service at `169.254.169.254` lives — multicast, and
  unspecified addresses are refused *even under `--hosts '*'`*. Reaching one
  requires naming its range in `--cidrs`, so an internal destination is always
  a sentence somebody wrote on purpose. The v4-in-v6 encodings
  (`::ffff:127.0.0.1`, NAT64, `::127.0.0.1`) are unwrapped before the check.
- **Quotas, mid-stream.** An over-budget transfer is cut while it is in
  flight, not flagged after it finishes.
- **TTL, mid-tunnel.** An open tunnel does not outlive its session, including
  when idle.

Every decision — allow and deny — lands in the same hash-chained audit log as
the credential broker, with the identity, task, host, port, byte counts, and
verdict, and no credential material.

**The tunnel is CA-free.** cloop does not terminate, inspect, or re-sign TLS,
and installs no certificate in the sandbox: the workload validates the origin's
certificate itself, exactly as it would without a proxy. That costs visibility
into tunnelled requests, deliberately — a proxy that could read every sandbox's
traffic would be a far more valuable thing to compromise than the credentials
it protects.

Revocation is immediate rather than TTL-bounded, which is the payoff for
brokering a *capability* instead of handing over a token: a leaked PAT cannot
be recalled from a running container, but a proxy session is torn down at the
proxy, mid-tunnel, by the control plane that holds it.

### Hardened (enterprise) configuration

By default cloop may run workloads as child processes of the control plane. To
guarantee that the web UI **never** spawns a harness on the host, turn host
execution off:

```yaml
executors:
  allow_host_process: false   # strict no-host-execution mode
  container:
    enabled: true             # …and give it somewhere else to run
```

or `cloop config set executors.allow_host_process false`.

This is the one setting a hosted deployment must flip. Absent means `true`, so
existing single-machine installs keep working across an upgrade.

With it `false`:

- the `localprocess` driver refuses to start anything;
- `executor.Resolve` refuses to hand that driver out, so background paths are
  covered too, not just the ones with an explicit check;
- every Web UI path that would have dispatched work returns **HTTP 409** with a
  machine-readable `code: host_execution_denied` and a `remediation` string
  naming the executors that *are* available; and
- the Executors tab shows the mode as a banner.

Hardening before any device has enrolled is a supported intermediate state —
remote executors arrive at runtime, not through this file — so the config still
loads and warns rather than refusing to boot.

The policy is a **ratchet**: it can only tighten at runtime. A control plane
manages many projects, each with its own `config.yaml`, and applying them
symmetrically would let a tenant re-enable host execution by editing a file they
control. Loosening requires a restart with a permissive config.

---


## Security Model

### What data leaves the machine

When you run cloop in any AI-powered mode (PM, suggest, explain, etc.) cloop sends
**only the following** to your configured AI provider:

| Data sent | When |
|-----------|------|
| Your project **goal** and **task descriptions** | Every prompt |
| **Step output** from previous tasks (for context) | When building task context |
| **Codebase snippets** injected by `--inject-context` or `cloop context` | When context injection is enabled |
| Git log / diff excerpts | Commands that require them (pr, commit-msg, trace, …) |

**No API keys, passwords, or environment variables** are ever included in prompts.
**No telemetry** is sent to Anthropic or any third party by cloop itself.

### API key storage

| Location | What is stored |
|----------|----------------|
| `.cloop/config.yaml` | API keys (optional — env vars are preferred) |
| Environment variables | Recommended: `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GITHUB_TOKEN` |
| `.cloop/state.db` | Goal, task list, step outputs — **no API keys** |

**Config file permissions:** cloop writes `.cloop/config.yaml` with mode `0600`
(owner read/write only). On load, cloop warns if the file has world- or
group-readable permissions so you can run `chmod 600 .cloop/config.yaml`.

**Encrypted secrets** (`cloop secret`) are stored in `.cloop/secrets.enc` using
AES-256-GCM and never written to any AI prompt.

### State file integrity (optional HMAC)

Set the `CLOOP_STATE_HMAC_KEY` environment variable to enable HMAC-SHA256
signing of exported state. The `pkg/security` package provides `Sign()` /
`Verify()` utilities; tooling that exports or imports state can use these to
detect tampering.

### Non-interactive access: API tokens

CI jobs, deploy scripts, and edge devices cannot hold a browser session. Give
them a **scoped API token** (`cloop_pat_…`):

```bash
# Read-only, one project, expires in 30 days
cloop hub token create ci-payments --role operator --project payments --expires-in 30d

cloop hub token list              # id, roles, scope, status, last use
cloop hub token list --active     # hide revoked and expired
cloop hub token revoke <id>       # effective on the next request
```

Or use the **Tokens** section of the Secrets panel, or `POST /api/tokens`.
Either way the value is printed **exactly once** — cloop stores a salted hash,
so a lost token is re-minted, never recovered.

A token is not an authorization bypass. It carries roles, and every RBAC check
applies to it exactly as it does to a signed-in user:

| Field | Meaning |
| --- | --- |
| `--role` | roles the bearer acts with (repeatable). You can only grant roles you hold yourself. |
| `--project` | restrict to these projects (repeatable). Out-of-scope projects are reported as nonexistent, not forbidden. |
| `--expires-in` | `90d`, `12h`, an RFC3339 timestamp, or `0` for no expiry. |

Use it as `Authorization: Bearer cloop_pat_…` (or `?token=…` for EventSource).
Minting requires the `token.admin` permission, which only `admin` holds; the
API additionally refuses to issue a token stronger or wider than its creator.
Creation, revocation, and every failed authentication are recorded in the audit
trail (`cloop events`).

### Web UI (`cloop ui`)

The web dashboard binds to **localhost only** by default.

> **`--token` / `CLOOP_UI_TOKEN` is deprecated.** It still works and will keep
> working, but it bypasses RBAC entirely, sees every project on the hub, and
> cannot be revoked for one caller without breaking every other. Mint a scoped
> API token per caller (above), then drop the flag and the environment
> variable. `cloop ui` prints a warning at startup while it is still set, and
> the Tokens panel shows a banner. See
> [Migrating off the static token](../security/model.md#migrating-off-the-static-token).

When a `--token` is set:

- Every `/api/*` request must present `Authorization: Bearer <token>` or
  `?token=<token>`.
- Failed authentication attempts are **rate-limited**: after 5 consecutive
  failures from the same IP the endpoint returns HTTP 429 and blocks that IP
  for 60 seconds.
- All responses include hardened HTTP headers:
  - `Content-Security-Policy` — restricts resource loading to same-origin
  - `X-Content-Type-Options: nosniff`
  - `X-Frame-Options: DENY`
  - `Referrer-Policy: no-referrer`
- CORS is restricted to `localhost` / `127.0.0.1` origins only (no wildcard).

### TLS

**Serving.** `cloop ui` and `cloop serve` can terminate TLS themselves, or sit
behind a proxy that does. Both are supported; a *half*-configuration is not —
a certificate without a key (or the reverse) fails at startup rather than
falling back to plaintext, because a server that quietly serves HTTP after
being asked for HTTPS is discovered from a packet capture, if at all.

```yaml
ui:
  external_url: https://cloop.example.com   # also an accepted WebSocket Origin
  allowed_origins: [ops.example.com]        # deployment-wide (dashboard + agents)
  allowed_ws_origins: [legacy.example.com]  # dashboard socket only
  tls:
    cert_file: /etc/cloop/tls/fullchain.pem
    key_file:  /etc/cloop/tls/privkey.pem   # mode 0600
    min_version: "1.2"                      # or "1.3"; 1.0/1.1 are rejected
```

Or per-invocation: `cloop ui --tls-cert <pem> --tls-key <pem>` (the flags
override the config block, as a pair). Only AEAD cipher suites with forward
secrecy are offered — no CBC, no static RSA. For local development,
`cloop hub tls-init` generates a self-signed pair (key written 0600 through
`pkg/atomicfile`, never briefly world-readable) and prints the pin to give
devices.

**HSTS and cookies.** Responses delivered over TLS carry
`Strict-Transport-Security: max-age=31536000; includeSubDomains`, and the OIDC
session cookie becomes `Secure` + `SameSite=Strict`. Both are keyed off the
request's real scheme, so they are also correct behind a TLS-terminating
reverse proxy (`X-Forwarded-Proto`, trusted only from a loopback peer). Neither
is applied on plaintext: HSTS on `http://localhost` would pin a developer's
browser to HTTPS for a year and break every other local project on that
hostname.

**WebSocket origins.** Both the dashboard socket and the executor-agent
endpoint accept an upgrade only from a recognised `Origin` — loopback,
same-origin, `ui.external_url`, or `ui.allowed_origins`. A request with *no*
`Origin` is allowed, because that is what every non-browser agent sends and a
browser cannot suppress the header. A cross-origin upgrade gets 403 with the
reason, before any token is examined — so it cannot burn a single-use
enrollment token on the way to being refused.

The two allowlists differ in blast radius and are deliberately not merged:
`allowed_origins` is deployment-wide and reaches `/api/executors/connect`,
where an entry can open an agent connection; `allowed_ws_origins` is scoped to
the dashboard socket only. Prefer setting `external_url` — it covers the
reverse-proxy case without either list.

Note that same-origin matching falls back to comparing hostnames when the
`Origin` and `Host` ports differ, which is what makes a proxy that rewrites
`Host` work. The consequence is that another *port* on the same hostname counts
as same-origin. If something you do not control is served from the hub's
hostname, set `external_url` and treat that hostname as part of the trust
boundary.

**Outbound.** All three remote providers (Anthropic, OpenAI, custom
OpenAI-compatible) and the executor agent validate certificates against the
system CA pool. There is **no `InsecureSkipVerify` option** in cloop, and
`tests/security/transport_test.go` fails the build if one appears on the
agent's dial path. Reaching a server with a private CA is done by *adding* a
root (`--ca-file`), not by removing verification.

For self-hosted models on plain HTTP (Ollama), set `ollama.base_url` to the
local endpoint. Outbound traffic to Anthropic/OpenAI is always TLS.

### Shell hooks and command injection

Pre/post task hooks (`hooks.pre_task`, `hooks.post_task`, etc.) are **user-
configured shell commands** from `.cloop/config.yaml`. Task context
(title, status, role) is passed as **environment variables** — never
interpolated into the hook command string — so task content cannot inject shell
commands through the hook mechanism.

### Dependency security

cloop uses `govulncheck` (golang.org/x/vuln) for dependency audits. The
`toolchain` directive in `go.mod` pins the minimum Go version to one that
resolves all known stdlib vulnerabilities.

