# Operator runbook

Backup and restore, audit verification, key rotation, upgrade and rollback for a
hosted cloop hub.

Command output below is real. Where a procedure has a sharp edge — an
unrecoverable key, a one-way migration — it is called out at the point where you
would otherwise walk into it.

- [Layout](#layout)
- [Health checks](#health-checks)
- [Backup and restore](#backup-and-restore)
- [Database maintenance](#database-maintenance)
- [Audit chain verification](#audit-chain-verification)
- [Key rotation](#key-rotation)
- [Upgrade](#upgrade)
- [Rollback](#rollback)
- [Fleet operations](#fleet-operations)
- [Incident playbooks](#incident-playbooks)

---

## Layout

```
.cloop/
  state.db                                canonical store (SQLite, WAL mode)
  state.db-wal  state.db-shm              WAL sidecars — never copy these by hand
  config.yaml                    0600     operator-written; safe to commit
  hub.env                        0600     CLOOP_SECRET_KEY, CLOOP_UI_TOKEN — never commit
  tls/cert.pem  tls/key.pem      0600     when the hub terminates TLS itself
  backups/state-<UTC>.db                  + a .db.meta.json sidecar per backup
```

Two rules that prevent most of the bad days:

1. **`hub.env` is not a config file, it is the key to every sealed secret.** Back
   it up separately from `state.db` and never in the same place — a backup that
   contains both is a plaintext secret store.
2. **Never copy `state.db` with `cp`.** Use `cloop db backup`, which produces a
   single self-contained file with no `-wal`/`-shm` dependency.

---

## Health checks

| Endpoint | Question | Behaviour |
| --- | --- | --- |
| `/healthz` | is the process alive? | never fails while it can accept a connection — do **not** wire a restart to a slow database |
| `/readyz` | should traffic come here? | three gates: the state database, then the identity provider, then the execution path. Fails during startup, on storage loss, while an issuer has never resolved, and when strict mode leaves no isolating executor registered |
| `/metrics` | Prometheus text | gated: requires the `audit.read` permission, unlike the two probes above |

`/healthz` and `/readyz` bypass auth and rate limiting so a probe can never be
locked out by a flood or a broken IdP. `/metrics` does not — it is an ordinary
authorised route, so a scraper needs a credential carrying `audit.read`. See
[Metrics](metrics.md).

The second and third gates are why a rollout of a misconfigured hub fails
instead of going green.

The identity gate covers the case that used to be invisible: a hub pointed at
an unreachable, misspelled or wrongly-registered issuer came up green and
failed for the first human who tried to sign in. It now resolves the issuer at
startup — discovery and the JWKS fetch — and reports `not_ready` with
`"check": "identity"` for as long as that has *never* succeeded. Once it has
succeeded once the gate stays open: existing sessions keep authenticating
through a later provider outage, and dropping the hub from its Service over one
would turn a login outage into a total one. Set `ui.oidc.require_idp` (or
`cloop ui --require-idp`) to refuse to start outright.

The execution gate is the older one. A hub with `allow_host_process: false` and
no container, Kubernetes or enrolled-agent executor can only answer a run
request with a 409, so it reports `not_ready` and the response body names the
fix:

```json
{
  "status": "not_ready",
  "check": "executors",
  "reason": "strict mode is on (executors.allow_host_process: false) and no isolating executor is registered, so every run would be refused",
  "remediation": "enable executors.container or executors.kubernetes in .cloop/config.yaml, enroll a remote agent (`cloop executor enroll`), or set executors.allow_host_process: true to permit un-isolated host execution"
}
```

The verdict is live, not a snapshot of startup: a hub that boots with nothing
isolating becomes ready the moment an edge device enrolls, with no restart.
An executor that registered but failed *preflight* is degraded, not missing —
it still satisfies this gate, because a cluster that was briefly unreachable
during boot should not keep a hub out of service until someone restarts it.

```console
$ cloop hub healthcheck --url https://hub.example.com --endpoint readyz
$ kubectl -n cloop exec deploy/cloop-cloop-hub -- /usr/local/bin/cloop hub healthcheck --endpoint readyz
```

The image is distroless — no shell, no `curl` — so this command *is* the
container's `HEALTHCHECK` and the Kubernetes exec probe. Options: `--timeout`
(default 3 s), `--ca-file` for a private CA. Exit 0 healthy, 1 not.

### Configuration health: `cloop hub doctor`

`healthcheck` answers "is it up". `doctor` answers "is it configured such that
it will keep working", which is a different question with a different failure
mode: a hub whose certificate expires next week, whose issuer moved, or under
whose RBAC policy nobody is an admin is green on both probes and broken.

```console
$ cloop hub doctor                    # in the hub's directory
$ cloop hub doctor --json | jq '.findings[] | select(.severity=="fail")'
$ cloop hub doctor --offline          # config only; contacts nothing
```

What it checks, and what each one catches that nothing else does:

| Group | Checks |
| --- | --- |
| `policy` | whether `executors.allow_host_process` was *decided* or merely defaulted |
| `oidc` | issuer discovery, the document's own issuer name, JWKS keys cloop can actually verify with, redirect URI origin and path against `ui.external_url`, client secret from the environment rather than the committed config |
| `tls` | cert and key are a matching pair, chain ordering, expiry (warns 30 days out), SANs cover the external hostname, key permissions, and the proxy-termination case |
| `secret_key` | `CLOOP_SECRET_KEY` present, and generated key material rather than a passphrase or a placeholder out of the docs |
| `rbac` | the mappings parse, the default role's blast radius, group bindings with no `groups` scope, and **whether anybody maps to admin** |
| `images` | policy validity, digest pinning, cosign actually installed when `require_signature` is on, the hub's own executor images against its own policy, and registry reachability |
| `executors` | reconciliation diagnostics, the strict-mode gate, and a liveness probe plus capability report per executor |
| `gitproxy` | whether pushes are brokered at all, TLS material, the branch allowlist and delete authority, and whether the advertised URL is one a sandbox could use — plus a bounded dial of it |
| `egress` | whether the broker is on, whether the advertised address is one a sandbox could use, a bounded dial of it, and the trap of an `internal: true` filter with no broker to proxy through |
| `storage` | `quick_check`, the schema version against this binary's — the rollback case, naming the build that moved the schema — and whether `CLOOP_ALLOW_SCHEMA_DOWNGRADE` is suppressing that guard |
| `config` | drift between `.cloop/config.yaml` and the copy mirrored in `state.db`, which is what "I changed that setting and nothing happened" usually is |
| `quotas`, `budget` | policy validity, limits set to `0` (which means *none allowed*, not unlimited), and unbounded spend on a multi-tenant hub |

Exit is 1 on any failure and 0 with only warnings, so it is usable as a
deployment gate. `--strict` fails on warnings too. Every non-pass finding
carries a one-line remediation; the `check` ids in `--json` are stable.

Two of those checks dial rather than read, because `executors.git_proxy.advertise_url`
and `executors.egress.advertise_addr` are the only config values a hub hands to a
sandbox and never uses itself — so a value that is right on the hub and unroutable
from a Pod is invisible everywhere else. The dial is bounded (3 s, or `--timeout`)
and never fails the run: the hub is not on the sandbox's network, and a Kubernetes
Service name that does not resolve on the hub is frequently the *correct* setting.
Read `gitproxy.advertise_reachable` and `egress.advertise_reachable` as "nothing is
listening" versus "this was never checked" — which were previously the same green
line. `--offline` reports them as skipped rather than passing.

Run it twice: once before the first `helm install` or `docker compose up`, and
once in CI against the config repo. `--offline` makes the second cheap.

---

## The control-plane lease

**One hub per `state.db`.** This is enforced, not advised: a hub takes a lease
at startup and a second one refuses to start.

The reason is not the file. SQLite's WAL keeps it perfectly consistent under two
writers, which is why this used to fail silently. What diverges is everything
the hub keeps *beside* it — the project-status cache, the run registry, chat
histories, live-log rooms and the WebSocket client set are all process memory,
and an event reaches only the clients of the process that produced it. A second
hub therefore serves a view that quietly stops agreeing with the first, while
running the same background sweeps and issuing its own stop signals for the same
runs.

```console
$ cloop hub lease status
Control-plane lease
  /srv/cloop/.cloop/state.db

  state      held
  instance   hub_59f28a07ceea8b8fa2b4386edc1cef40
  host       hub-1 (pid 1234)
  serving    :8080
  acquired   2026-09-12T17:23:15Z
  last beat  11s ago
  lapses in  49s if the holder stops renewing
```

### How it behaves

| Situation | What happens |
| --- | --- |
| Clean shutdown (SIGTERM, `helm upgrade`, `systemctl restart`) | The lease is released after requests drain. The replacement starts immediately. |
| Hub killed outright (SIGKILL, OOM, node crash) — same host | The successor probes the recorded pid and takes over at once. No wait. |
| Hub gone on another host, or after a reboot | The pid cannot be trusted, so the lease lapses on its **last heartbeat + 60s** and the next start succeeds. |
| A hub is paused past the TTL and its lease taken | Its next renewal fails, it logs `standing down`, drains and exits non-zero. It does **not** keep serving. |
| A second hub started deliberately | Refuses with an error naming the holder's host, pid and port. |

Nothing here needs an operator in the normal case, including the crash case.
That is the point of a lease rather than a lock file: a stale lease is free, so a
dead hub cannot wedge its own restart.

### When a hub refuses to start

```
Error: another cloop hub already controls this state (/srv/cloop/.cloop/state.db)

  holder     hub_59f28a07… on hub-1 (pid 1234), serving :8080
```

Treat this as correct until proven otherwise — it is reporting a second hub, and
the fix is almost always to stop that one. In order:

1. `cloop hub lease status` — is the holder this machine? Is its pid alive?
2. If the holder is alive, stop it. Under Kubernetes check for a second Pod;
   `replicaCount` above 1 is the usual cause and the chart now refuses to render
   with it.
3. If you want two dashboards on purpose, give the second one its **own
   directory**. A hub roots its control plane at its working directory, so a
   second one needs a second one. They will not share state — that is the whole
   constraint — but both can watch the same registered projects.
4. If the holder is genuinely gone, wait for `lapses in` to reach zero and start
   again. `cloop hub lease clear` does it explicitly, and refuses while the lease
   is live. There is no `--force`: a live lease means a hub is renewing it right
   now, and evicting it would create exactly the split-brain the lease prevents.

---

## Backup and restore

### Backup

`VACUUM INTO` under a read transaction: safe while the hub is running and while
tasks are executing.

```console
$ cloop db backup
cloop db backup
  source: /srv/cloop/.cloop/state.db
  output: /srv/cloop/.cloop/backups/state-20260822T095227Z.db

  WAL checkpoint:  TRUNCATE log_frames=0 checkpointed=0
  size:            320.0 KB
  duration:        19ms
  sha256:          bbedb9d5f45fd4bf8fb368b60c29c7cb7cb60d3dac608229cf1bcee5d63292ed
  schema version:  15
  metadata:        /srv/cloop/.cloop/backups/state-20260822T095227Z.db.meta.json

Backup complete.
```

`--output <path>` overrides the destination. The `.meta.json` sidecar records the
SHA-256, size, source, schema version and duration; restore checks the digest
against it. Keep the sidecar with the backup — losing it costs you the integrity
check, and restore will then need `--skip-checksum`.

A backup contains **sealed** secrets. It is not plaintext, but it is one half of
a plaintext secret store; the other half is `hub.env`.

Nightly, with retention:

```bash
cloop db backup --output /var/backups/cloop/state-$(date -u +%Y%m%dT%H%M%SZ).db
find /var/backups/cloop -name 'state-*.db*' -mtime +30 -delete
```

### Restore

```console
$ cloop db verify                                   # check the live db first
$ cloop db restore /var/backups/cloop/state-20260822T095227Z.db --force
```

`--force` is required when a live database is present. Before overwriting,
restore moves the existing file aside as `.pre-restore.<UTC>` — so a restore of
the wrong backup is itself reversible. `--skip-checksum` proceeds without the
metadata sidecar.

Restore validates with `PRAGMA integrity_check`, the SHA-256, and a schema sanity
check before it writes anything.

**Restoring a hub is a two-part operation.** Restoring `state.db` alone gives you
a database full of secrets you cannot unseal. Restore the matching `hub.env`
(specifically `CLOOP_SECRET_KEY`) too, or every stored secret is lost.

Order of operations for a full restore:

1. stop the hub (do not restore under a running process)
2. restore `hub.env` — the matching `CLOOP_SECRET_KEY`
3. `cloop db restore <backup> --force`
4. `cloop db verify`
5. start the hub, confirm `/readyz`
6. `cloop audit-log verify`
7. `cloop executor ls` — enrolled agents reconnect on their own backoff

---

## Database maintenance

```console
$ cloop db verify            # integrity_check + foreign_key_check (read-only)
$ cloop db verify --quick    # quick_check — faster, less thorough
```

Exit codes: 0 pass, 1 issues found, 2 the check could not run.

```console
$ cloop db maintain --dry-run
cloop db maintain — dry-run (size report only)
  database: /srv/cloop/.cloop/state.db

  size before:    320.0 KB (80 pages, 4096 bytes/page, 0 freelist)
  last maintenance: never

Dry run — no changes written.
  estimated reclaim: 0 B (freelist_count × page_size)
```

`cloop db maintain` runs `VACUUM` + `ANALYZE` and records the run in
`maintenance_log`. `--auto` skips unless the database has grown more than 20 %
since the last vacuum, which is what you want in a cron entry:

```bash
0 4 * * *  cloop db maintain --auto
```

`VACUUM` rewrites the database and needs free space roughly equal to its size.

---

## Audit chain verification

`audit_events` is hash-chained: each row's `row_hash` covers its content and the
previous row's hash. Editing or deleting a row breaks the chain from that point.

```console
$ cloop audit-log verify
OK — 8 events verified
```

Exit 0 intact, 2 broken — and on a break it names the row id and the reason.
**Run this on a schedule and alert on exit 2**; a chain break is either
corruption or tampering, and both want a human.

What the chain does and does not prove: it detects modification and insertion
anywhere in the history, and deletion anywhere except the tail. Truncating the
newest rows leaves a shorter, still-valid chain. Regular export off-box is what
closes that gap.

```console
$ cloop audit-log list --entity secret --since 7d
$ cloop audit-log list --actor alice@example.com --type run.start --json

$ cloop audit-log export --format jsonl --since 24h --verify --output /var/log/cloop/audit.jsonl
$ cloop audit-log export --format cef  --since 24h --verify | logger -t cloop -p local0.notice
```

| Format | Use |
| --- | --- |
| `jsonl` | lossless, structured payloads — the archival format |
| `csv` | flat table for spreadsheets |
| `cef` | ArcSight Common Event Format, syslog-ready |

### Retention: keeping the trail bounded

The trail only grows, and on a busy hub it grows fast enough to matter — this
project's own control plane reached 1.1M rows and 2.4 GB. Retention moves the
old prefix out of the database without breaking verification.

It is **opt-in**. With no `audit.retention_days`, nothing is ever pruned.

```yaml
audit:
  retention_days: 90            # 1–3650; 0 or absent keeps everything
  export_dir: /srv/audit-archive # default: .cloop/audit-archive
  prune_on_maintain: true       # let `cloop db maintain` apply it
```

A prune never simply deletes. It streams the prefix to a JSONL archive,
chain-verifies every row on the way out, digests the file, and only then
removes the rows — recording an *anchor* holding the boundary hash, the id the
chain resumes at, and the archive's SHA-256.

```console
$ cloop hub audit prune --before 90d --dry-run
$ cloop hub audit prune --before 90d
$ cloop hub audit anchors        # every truncation, oldest first
$ cloop hub audit verify-seals   # re-hash each archive against its anchor
```

After a prune, `cloop audit-log verify` walks *across* the gap using the anchor
and still reports OK. That is not a relaxation: the anchor pins the id the
chain must resume at, so deleting a few more rows just past the boundary is
still caught.

Three things worth knowing:

- **Pruning does not shrink the file.** It frees pages onto SQLite's freelist.
  Run `cloop db maintain` to return them to the filesystem. That command
  VACUUMs, which rewrites the whole file, so it **refuses while another hub
  holds the control-plane lease** — stop the peer or wait for the lease to
  lapse (`cloop hub lease status`).
- **`verify-seals` is the check that leaves the database.** Chain verification
  can only prove the survivors agree with what the anchors claim, and anyone
  who can rewrite `audit_events` can rewrite `audit_anchors` too. Copy the
  archives somewhere the hub cannot write; that copy is the real evidence.
- **A pruned trail can no longer be replayed from the beginning.**
  `cloop events replay` refuses rather than silently rebuilding a partial
  database, and names the archive holding the missing events. Pass
  `--allow-truncated` to rebuild just the surviving tail on purpose.

`--verify` refuses to export a broken chain, so an exported file is one that
passed verification at export time. Every format carries `prev_hash` and
`row_hash`, letting the recipient re-verify independently. Filters: `--actor`,
`--entity`, `--entity-id`, `--type`, `--since`, `--until`, `--limit`. Output files
are written 0600.

Audit rows never contain credential material — that is asserted by
[five separate checks](../security/model.md#secret-non-disclosure--secrets_testgo-audit_testgo-uiroutes_testgo),
including one that scans *every* row rendering rather than a sample.

---

## The git interception proxy

Off by default. With it on, a sandbox that fetches and pushes the project's
source never holds the forge PAT — it gets a session token for a proxy the hub
runs, which enforces the branch allowlist on the push's own ref-update list. The
design is in [git interception proxy](../git-interception-proxy.md); this is the
operational part.

### Turning it on

1. **Give it a certificate the sandbox will accept.** This is the step that gets
   missed: the certificate is validated by *the sandbox's* git, not by the hub.
   A public-CA certificate needs nothing further; a self-signed or private-CA one
   needs its CA in the sandbox image's trust store, or in a bundle named by
   `SSL_CERT_FILE` / `GIT_SSL_CAINFO` on the machine git runs on.
2. **Decide what the sandbox can reach.** `listen_addr` is the bind address;
   `advertise_url` is what becomes the sandbox's remote, and it has to route
   from where git actually runs — a Service for the Kubernetes backend, the
   hub's address on the link for an edge device. The
   [table of forms](../git-interception-proxy.md#advertise_url-what-the-sandbox-can-reach)
   covers the rest.
3. **Write the section and restart the hub.**

   ```yaml
   executors:
     git_proxy:
       enabled: true
       listen_addr: "0.0.0.0:8443"
       advertise_url: "https://hub.internal:8443"
       cert_file: /etc/cloop/tls/git-proxy.crt
       key_file: /etc/cloop/tls/git-proxy.key
       session_minutes: 60
   ```

4. **Confirm it came up.** One line on stderr names the bind address, what
   sandboxes are pointed at, and the allowlist:

   ```
   ui: git interception proxy on 0.0.0.0:8443, advertised as https://hub.internal:8443; pushes limited to refs/heads/cloop/**
   ```

5. **Run one task on the executor** and check the audit trail for the session and
   the fetch: `cloop audit-log list --entity gitproxy --since 1h`.

Two failure lines matter, and both mean the boundary is not in effect:
`ui: git interception proxy NOT started: …` (the whole hub is unprotected — every
dispatch after it hands out the PAT) and `ui: executor <id> is NOT routed through
the git proxy: …` (one executor is). The hub deliberately still boots, so these
are worth alerting on rather than relying on a failed start. A third,
`ui: git proxy decisions will go to stderr, not the audit trail: …`, is smaller:
the proxy still refuses what it should, the evidence just is not in the database.

### Session lifetime is not run lifetime

A session lives for `session_minutes` (60 by default, 720 maximum) from
*dispatch*, and nothing closes it when the run ends. **A run that outlives its
session fails its push** with an authentication error from git and a
`gitproxy.rejected` row. Set the TTL against the longest run the hub is expected
to finish, not the median one.

There is no command that ends one session early. Sessions live in the hub's
memory, so a hub restart closes every live one — recorded as
`gitproxy.session_closed` with the reason *"the hub is shutting down"* — and
short of that a session expires on its own TTL, which is enforced at
authentication whether or not the five-minute reaper has swept it. That is the
blunt instrument; the sharp one is
revoking the underlying grant with `cloop secret revoke`, which stops the *next*
dispatch from minting anything, and rotating the PAT at the forge.

### Alert on `gitproxy.push_denied`

```console
$ cloop audit-log list --type gitproxy.push_denied --since 7d
$ cloop audit-log list --entity gitproxy --since 24h --json
```

A `push_denied` row is a sandbox that tried to move a ref outside its allowlist —
`refs/heads/main`, say — and was refused before anything was forwarded to the
forge. It is the only place that attempt is written down; nothing else in cloop
records it, because without the proxy nothing else is on the path.

It is not a noisy signal to be tuned away. A well-behaved task never produces
one, so each occurrence is either a workload doing something it was not asked to
do or a policy narrower than the task it was minted for, and both want a human.
Its sibling `gitproxy.push_allowed` is emitted *before* forwarding, so a
`push_allowed` with no matching change on the forge means the forge refused it —
branch protection, a non-fast-forward — not that the proxy did.

---

## Key rotation

Three different keys, three different procedures. The sealing key rotates
online with `cloop hub key rotate`; the TLS key rotates in a staged overlap; the
dashboard token rotates by replacement and causes a logout.

### TLS certificate and agent pins — supported, staged

Agents pin the hub's **SPKI** (a hash of the public key), not the certificate. So
a routine renewal that reuses the key does **not** change the pin, and an
enrolled fleet survives renewal with no action.

```console
$ cloop hub pin                          # from ui.tls.cert_file
$ cloop hub pin --cert /path/new.pem     # the pin of a certificate you are about to roll onto
```

Rotating onto a **new key** does change the pin. Stage it — agents accept a
comma-separated pin set precisely so the two can overlap:

1. `cloop hub pin --cert new.pem` to get the incoming pin
2. distribute `--pin <old>,<new>` to agents and restart them
3. roll the hub onto the new certificate
4. confirm `cloop executor ls` shows every agent reconnected
5. redistribute with only `<new>`

Reversing steps 2 and 3 locks every agent out. `cloop hub tls-init` generates a
self-signed certificate for development only.

The [git proxy](#the-git-interception-proxy) has its own `cert_file` and
`key_file` and is not covered by any of the above. Nothing pins it, but its
certificate is validated by every sandbox's git, so a rotation onto a new CA has
to reach the sandbox image's trust store *before* the hub starts serving it —
otherwise the first symptom is every provisioning fetch failing to verify the
peer.

### Dashboard token (`CLOOP_UI_TOKEN`) — manual, causes a logout

Generate 32 random bytes, replace it in `hub.env` (or the Kubernetes Secret),
restart. All token-authenticated clients must be updated; OIDC sessions are
unaffected. There is no overlap window, so schedule it.

### Enrollment tokens and agent credentials — revoke and re-enrol

```console
$ cloop executor agents                  # enrolled agents + outstanding tokens
$ cloop executor revoke <token-id|agent-id>
$ cloop executor enroll --name edge-1 --ttl 15m
```

Revocation cascades from the enrollment record to the credential derived from it,
and the hub sends `bye` with `reconnect=false` so the agent stops rather than
retrying. Enrollment tokens expire on their own (15 min default, 24 h max);
**agent credentials do not expire** — revocation is the only way to end one.

On a device running the installed service, re-enrolling means replacing the
credential file rather than editing the unit:

```console
# on the device, as root
$ install -m 0600 /dev/null /var/lib/cloop-executor/enrollment
$ printf '%s\n' "$CLOOP_ENROLL_BUNDLE" > /var/lib/cloop-executor/enrollment
$ rm -f /var/lib/cloop-executor/agent.json      # drop the revoked identity
$ systemctl restart cloop-executor
```

The agent removes the enrollment file once it has redeemed the token, so an
empty `/var/lib/cloop-executor/enrollment` on a healthy device is expected, not
a fault. To remove the device entirely, `cloop executor agent install
--uninstall --purge` — idempotent, and it verifies afterwards that no unit,
credential or state directory survives.

### Sealing keys — online, resumable, no credential re-minting

Stored credentials are not encrypted under `CLOOP_SECRET_KEY` directly. Each row
gets its own random **data-encryption key** (DEK) which seals the payload; only
the DEK is sealed under a **key-encryption key** (KEK) derived from the
passphrase. Rotating therefore rewraps sixty bytes per row and never decrypts a
payload, which is what makes it safe to run against a serving hub.

Several KEKs can be openable at once. Rows move to the new one individually and
reads keep succeeding against whichever key each row still names, so there is no
window in which anything is unreadable.

```console
$ cloop hub key status                   # which key is sealing what
$ cloop hub key rotate --dry-run         # count what would move
$ cloop hub key rotate                   # mint a new KEK and rewrap onto it
$ cloop hub key list                     # keys, and whether each is still openable
```

`rotate` covers **both** populations of long-lived sealed material — brokered
secrets and session refresh tokens — because they share one registry. Enrollment
tokens and agent credentials are not covered and do not need to be: they are
stored as SHA-256 hashes, never sealed, so no key can be rotated out from under
them (see [enrollment tokens](#enrollment-tokens-and-agent-credentials--revoke-and-re-enrol)).

**Interruption is safe.** Ctrl-C, a restart, a SIGKILL mid-write — the row in
flight is transactional and everything else is untouched, because rotation
retires nothing and the old key stays openable. There is no cursor to corrupt:
the work remaining is defined as "every row not yet under the target key", so
resuming is just running it again.

```console
$ cloop hub key rotate --continue        # resume onto the current primary
```

**Concurrent writes are not lost.** Each rewrap is a compare-and-swap against
the exact ciphertext that was read. A credential re-minted, or a session
refreshed, while a rotation is running is left alone and counted as *skipped*;
run `--continue` once afterwards to sweep those up.

**Run one rotation at a time.** Two concurrent runs each promote their own key
and pull rows back and forth. cloop detects this — a row that keeps returning is
reported and the run exits incomplete rather than looping forever — but the work
is wasted. If you see `still not under ... after 5 attempts`, check for a second
`cloop hub key rotate`, then `--continue`.

A hub that is *serving* while you rotate needs no coordination: it re-reads the
current primary before every seal, so new material lands under the new key from
the moment it is promoted, and it adopts that key on first use.

#### Retiring the old key — a deliberate second step

Rotation never destroys a key. Retirement does, and it is irreversible: it
blanks the KEK's salt so the key cannot be derived from `CLOOP_SECRET_KEY`
again, at all. Anything still sealed under it is then unrecoverable, which is
why retirement **refuses** while any row references the key.

```console
$ cloop hub key status                   # must report zero unrotated rows
$ cloop hub key retire <old-key-id> --yes
```

After retirement, a read of material still naming that key fails loudly and
specifically — `sealing key retired`, naming the key and when — rather than as a
generic decryption error. That distinction is the point: it tells you to
re-mint the credential rather than to go hunting for a passphrase problem.

#### Changing `CLOOP_SECRET_KEY` itself

Rotating the KEK does **not** change the passphrase — every KEK is derived from
it. Changing the passphrase is still a re-mint, and cloop now refuses to paper
over it: a hub started with a passphrase that cannot derive its live keys fails
to start, naming them, rather than minting a fresh key and quietly forking the
registry.

If you must change the passphrase:

1. `cloop secret grants --all > grants.txt` — record what exists (never the values)
2. `cloop db backup` and copy the **old** `hub.env` somewhere safe
3. rotate the underlying credentials at their sources (GitHub, cluster, registry)
4. set the new `CLOOP_SECRET_KEY`, restart the hub
5. `cloop secret mint` each secret with its new value
6. `cloop secret grant` to reconstruct the grants from `grants.txt`
7. `cloop secret lease --project <p>` to confirm delivery

Because step 3 is required regardless, treat *passphrase* rotation as credential
rotation. For everything short of that — a scheduled key roll, a suspected key
exposure, an audit requirement — `cloop hub key rotate` is the procedure, and it
needs none of the above.

#### Upgrading a hub that predates envelope encryption

Migration `0019_envelope_encryption.sql` stamps every pre-existing row
`legacy` and adds the columns; it cannot re-encrypt anything, because SQL cannot
decrypt. Those rows keep opening under the old construction until the first
rotation converts them:

```console
$ cloop hub key status                   # shows N rows as "pre-envelope"
$ cloop hub key rotate                   # upgrades them, once, permanently
```

Nothing breaks if you never run it. But until you do, those rows are outside the
rotation guarantee, and `status` will keep saying so.

### Grants — rotate by expiry, not by procedure

Short TTLs mean grants rotate themselves. See
[choosing TTLs](../guides/secrets.md#choosing-ttls).

---

## Upgrade

Schema migrations live in `pkg/statedb/migrations/`, numbered from `0001_init.sql`,
are embedded in the binary, and are applied automatically by `statedb.Open()` on
every start. Each runs in a transaction and records itself in `schema_migrations`
— together with the version of the binary that applied it — so a crash
mid-migration rolls back cleanly and the next start retries.

**There are no down-migrations. Migration is roll-forward only** — which is why
step 1 below is not optional.

```console
$ cloop db backup                        # 1. NOT optional — the only way back
$ cloop migrate --dry-run                # 2. what would change
$ cloop version                          # 3. install the new binary
$ cloop migrate                          # 4. or just start the hub; Open() migrates
$ cloop db verify                        # 5.
$ cloop hub healthcheck --endpoint readyz
$ cloop audit-log verify
```

Rolling the container image:

```bash
docker pull ghcr.io/blechschmidt/cloop:<new>
docker stop hub && docker rm hub
docker run -d --name hub ... ghcr.io/blechschmidt/cloop:<new>
```

Helm:

```bash
helm upgrade cloop deploy/helm/cloop-hub --namespace cloop \
  --set image.tag=<new> --wait --timeout 5m
```

`--wait` returns only once the readiness probe passes, which means the PVC
mounted, the ConfigMap landed, and SQLite opened under `readOnlyRootFilesystem`
and `runAsNonRoot`. Pin images by **digest** in production — cloop does not
verify image signatures.

Enrolled agents reconnect on their own backoff (1 s → 2 min); they do not need
upgrading in lockstep, but check `cloop executor ls` afterwards. Confirm
`cloop executor list` still shows the expected backends and that
`executors.allow_host_process` is still `false` — a config merge that silently
re-enables host execution is the regression worth looking for after every
upgrade.

---

## Rollback

**A newer schema cannot be opened by an older binary once the difference
matters**, and there are no down-migrations. This is enforced, not merely
advised: an older binary compares the database's recorded version against the
highest migration it embeds and, for every version it is missing, asks what that
migration did.

Each migration is classified when it is applied and the verdict is stored in
`schema_migrations.compat`. A migration that only *added* objects — new tables,
new non-unique indexes, new views — is `additive`: a binary that predates it has
no statement that can name them, so their presence changes nothing it does. A
migration that altered, dropped or constrained something that already existed is
`breaking`. Anything unclassified, including rows written by a build that
predates this bookkeeping, counts as breaking.

A database whose extra migrations are all additive opens normally. Otherwise the
binary refuses, naming both versions, the build that moved the schema forward,
and which migrations specifically are incompatible.

```console
$ cloop ui
Error: statedb: database schema is newer than this binary: database is at schema
version 30 but this binary carries 29 (applied by cloop v0.4.0 as
0030_widget_policy.sql at 2026-05-02T09:14:22Z); … Incompatible:
0030_widget_policy.sql. …
```

The refusal happens before the hub binds a port or takes the control-plane
lease, so a rolled-back image fails its health check instead of serving from a
schema it half-understands. Every command goes through the same path, and
`cloop hub doctor` reports it as `storage.schema` without needing the hub to be
startable — run that first when a rollback will not come up.

Rollback is therefore *restore*, not *downgrade*:

1. stop the hub
2. install the previous binary or image tag
3. `cloop db restore <backup taken before the upgrade> --force`
4. `cloop db verify`
5. start; check `/readyz`, then `cloop audit-log verify`

### When the schemas are known-compatible

Purely additive gaps are handled automatically and need no intervention — see
above. The escape hatch is for the rest: a migration classified `breaking` that
you have read and judged harmless for your rollback, or one left unclassified by
a build too old to record a verdict. If you have checked the migrations between
the two versions and none of them touches what the older build uses,
`CLOOP_ALLOW_SCHEMA_DOWNGRADE=1` opens the database anyway:

```bash
CLOOP_ALLOW_SCHEMA_DOWNGRADE=1 cloop ui
```

This is an escape hatch for a rollback you have already reasoned about, not a
default. `cloop hub doctor` reports the variable being set as its own finding —
`storage.schema_guard`, a warning on its own and a failure while a skew is
actually present — so an exemption left in a Deployment manifest does not
quietly outlive the incident that justified it. Unset it once the rollback is
over.

Everything between the backup and the rollback is lost — task state, audit rows,
grants minted in the window. If that window is unacceptable, export the audit
trail before upgrading:

```bash
cloop audit-log export --format jsonl --verify --output pre-upgrade-audit.jsonl
```

The `.pre-restore.<UTC>` file that restore leaves behind is your way back out of a
bad rollback. Do not clean it up until the rollback is confirmed good.

---

## Fleet operations

```console
$ cloop executor list                    # registered backends and what they isolate
$ cloop executor ls                      # health, in-flight work, last contact
$ cloop executor test container          # preflight: run `cloop version` inside it
```

`list` states the sandbox type per executor, including `hypervisor-backed` for
one configured with a Kata runtime. `test` is what proves it: on a Kata executor
it additionally checks that the runtime name is registered with the CLI and that
`/dev/kvm` opens, then boots a real workload — see
[the Kata guide](../guides/kata.md#verifying-it).

Taking a node out of service:

```console
$ cloop executor cordon edge-01 --reason "kernel patch"   # no new work; running work continues
$ cloop executor drain  edge-01                            # no new work; wait for zero in-flight
$ cloop executor uncordon edge-01                          # back to whatever the probes justify
```

`uncordon` does not optimistically mark the node ready — it returns it to the
state its probes justify.

If a node dies rather than draining, the supervisor does it for you: three missed
heartbeats (~45 s) mark it `unreachable` and in-flight sessions are re-placed on
surviving nodes exactly once. See
[failover](../architecture/executors.md#failover-task-20162).

```console
$ cloop executor reap container          # remove sandbox containers/Pods left by earlier runs
```

`reap` takes an executor ID — it acts on one backend, not the fleet. Since Task
20191 a hub reaps on its own at startup, so this is for cleaning up after a hub
that is *not* running, or for a runtime shared with one that never will be.

### After a control-plane restart

A hub that is killed mid-run does not lose the workloads it dispatched: the
containers, Pods and edge-device processes keep running, and on the next start
each driver reattaches to its own from `executor_handles`. What is left over
after that — session rows nothing will close, workloads nothing can reattach to,
worktrees nothing will merge — is swept in the background, bounded at two
minutes, so a git prune and a runtime listing never delay the listener. See
[durable handle identity](../architecture/executors.md#durable-handle-identity-task-20191).

The sweep reports what it did through the hub's normal log, prefixed `ui:` under
`cloop ui` and `apiserver:` under `cloop serve`. The lines worth recognising:

```
executor: 3 in-flight session(s) reattached to a still-running workload
executor: closed 1 stale in-flight session(s) left by a previous control plane (drain would otherwise have waited on them forever)
executor container: garbage-collected 2 exited container(s) from a previous run: cloop-app-a1b2, cloop-app-c3d4
executor container: killed 1 container(s) still running from a previous control plane: cloop-app-e5f6
executor: pruned 2 leaked task worktree(s) in /srv/app: worktree gc: removed 2 worktree(s) and 0 branch(es); kept 5; 0 error(s)
```

**"reattached" is the good line.** Those runs survived the restart: their output
continues in the dashboard and their exit codes are still collected.

**"killed N container(s) still running from a previous control plane" is the one
to read carefully.** It means a sandbox was *executing a harness* when it was
collected — work in progress was destroyed, not litter tidied away — and it is
deliberately worded differently from the "garbage-collected N exited" line so the
two are distinguishable in a log. It fires only for a container older than the
[grace period](../reference/configuration.md#container-sandbox) that carries this
executor's own labels and that no live handle claims, which after a healthy
restart should be nothing: rehydration adopts what it can, so anything reaped was
dispatched by a process with no handle store or one whose rows were lost. Seeing
it routinely means handle persistence is not working — check the startup log for
`handle persistence unavailable`, which names the reason and warns that workloads
dispatched by that process will not survive a restart.

`localprocess` is the driver that recovers least, and an operator will see it in
the run's own log rather than the hub's. A host workload that survived a restart
carries a `[cloop]` line saying its live output was lost with the pipe that
carried it, and that the process is still being watched; one whose pid was
recycled, or whose host rebooted, is reported `failed` with exit code `-1` and a
message naming which. That is honest rather than pessimistic — the exit status of
a process this hub was never the parent of genuinely cannot be collected, and
reporting `exited(0)` would mark failed work as done.

### A drain never finishes

`cloop executor drain <id>` (and the dashboard's drain button) waits for the
executor's in-flight session count to reach zero and gives up with
`ErrDrainTimeout`. Before Task 20191, a hub that restarted while a run was in
flight left a `running` row in `executor_sessions` that nothing would ever
close, so drain timed out on that executor *permanently* — the count never moved,
and no amount of waiting helped.

The startup sweep is the fix, so the first thing to try is a restart of the hub:
it closes rows whose executor no longer knows the handle. If drain still hangs
after that, the count is real and the sweep has deliberately left the rows alone
— `sessionOutcome` treats a driver that cannot answer (an unreachable cluster, a
device that has not dialled back in) as *live*, because closing a session whose
workload is actually running would let the scheduler re-place its task and put
two agents in one repository. Check the executor's health with `cloop executor
ls` and fix the reachability. `--force` stops *waiting* rather than failing — the
node stays draining, and the sessions it reports are still running and were not
touched.

### Pruning leaked worktrees by hand

Parallel task execution gives each task a git worktree under
`.cloop/worktrees/task-<id>` on a `cloop/task-<id>-<slug>` branch. A run killed
between creating the worktree and merging it leaks both. The hub collects the
*directories* on its next start, older than two hours and skipping any task it
believes is still running; it never touches a branch, because an unmerged one is
the only copy of that task's work.

```console
$ cloop worktree list                              # what is on disk, what git knows, and how old
$ cloop worktree prune --dry-run                   # the plan, including the branches it would keep
$ cloop worktree prune                             # remove directories older than 2h
$ cloop worktree prune --delete-branches           # …and merged cloop/task-* branches
```

Run these from inside the repository — both act on the current working
directory. `list` shows two shapes that are both leaks and both invisible to a
sweep that looks at only one source: a directory git no longer registers (`GIT`
`no`), and a registration whose directory is gone (`DIR` `no`).

`--min-age 0` disables the age guard and is the one flag here that can destroy
work: a live parallel run's worktrees are in that directory *right now*, and git
cannot restore what was never committed. Use it only when you have established
that nothing is running. `--delete-branches` is safe by comparison — it deletes
only branches already contained in the base branch (`--base`, defaulting to the
checked-out one), the check is enforced twice, and `git branch -d` refuses
unmerged work on its own authority. A branch reported as kept because it "is not
merged" is the API declining to destroy the only copy of a task's work; merge or
delete it yourself.

A non-zero exit from `prune` means some worktree could not be removed — a
permission error, a busy mount — and names it. The rest were still collected.

---

## Incident playbooks

### Access emergencies

Three sequences you can paste. They exist as CLI commands rather than only as
dashboard actions because the situations that call for them are the ones where
a browser is the wrong tool or is not available: the listener is wedged, you are
on the host over SSH, or the account you need to contain is the one that would
be doing the containing.

Every mutation takes a required `--reason` and records it in the hash-chained
audit trail along with the OS user who ran it, so `cloop audit-log list` answers
"who did this, when, and why" without anybody reconstructing it from memory.
Read them back with:

```bash
cloop audit-log list --entity session --since 24h
cloop audit-log list --entity role_binding --since 24h
cloop audit-log list --entity quota --since 24h
```

#### A session was stolen

Contain the session, then the credentials behind it. Order matters: revoking the
session first stops the active use while you work out what else the account
holds.

```bash
# 1. See what the account has open, and from where. The IP column is usually
#    what tells a stolen cookie from the user's own second browser.
cloop hub session list --identity alice@example.com

# 2. End one session, or all of theirs.
cloop hub session revoke 3f9c1e7a2b5d48c0 --reason "reported stolen laptop, INC-4412"
cloop hub session revoke --identity alice@example.com --reason "credential compromise INC-4412"

# 3. Sessions are not the only credential. Revoke any API token the account holds.
cloop hub token list
cloop hub token revoke <token-id>

# 4. If the account itself is suspect rather than just one cookie, demote it too
#    — see "A compromised admin" below.
```

```console
$ cloop hub session list --identity alice@example.com
ID                IDENTITY           IP             IDLE  EXPIRES            IDP CHECKED
3f9c1e7a2b5d48c0  alice@example.com  198.51.100.24  3s    2026-09-14 23:49Z  never
a1d4f80b6c2e93aa  alice@example.com  203.0.113.9    17m   2026-09-14 23:49Z  never

$ cloop hub session revoke --identity alice@example.com --reason "credential compromise INC-4412"
Revoked 2 session(s).
  3f9c1e7a2b5d48c0  alice@example.com
  a1d4f80b6c2e93aa  alice@example.com

A running hub may still honour these for up to 30s (its session cache).
API tokens are a separate credential — see `cloop hub token list`.
```

**The 30 seconds are real.** A running hub serves sessions from a per-process
cache with that TTL, which is the same bound it already accepts between
replicas. "I revoked it and they were still in" for a few seconds is this, not a
failure. If you need the window closed to zero, stop the hub.

This command reads and writes the session table directly and takes no
control-plane lease, which is deliberate: the case it exists for is a hub whose
listener is wedged, and that hub is still holding its lease.

#### A tenant is running away

One identity is consuming the shared budget, executor slots, or project count.
Cap it now and work out why afterwards.

```bash
# 1. What is this identity actually consuming?
cloop hub quota list

# 2. Cap it. The override is sparse — setting one ceiling leaves every other
#    one exactly as it was, inherited or overridden.
cloop hub quota set alice@example.com \
  --limit daily_cost_usd=5 \
  --limit max_concurrent_tasks=2 \
  --reason "runaway plan INC-4413"

# 3. Stop what is already running, which the cap does not do by itself.
cloop hub session revoke --identity alice@example.com --reason "runaway plan INC-4413"

# 4. Afterwards: drop one ceiling back to configured policy, or all of them.
cloop hub quota set alice@example.com --unset max_concurrent_tasks --reason "tasks back to policy"
cloop hub quota clear alice@example.com --reason "INC-4413 closed"
```

```console
$ cloop hub quota set alice@example.com --limit daily_cost_usd=5 --limit max_concurrent_tasks=2 --reason "runaway plan INC-4413"
Quota override for alice@example.com:
  max_concurrent_tasks         2
  daily_cost_usd               5

Takes effect when the hub next starts — it loads overrides once. Start it now,
or apply the same change through the Quotas panel on a running hub.

$ cloop hub quota list
IDENTITY           RESOURCE              OVERRIDE  USED  UPDATED BY
alice@example.com  max_concurrent_tasks  2         -     cli:root
alice@example.com  daily_cost_usd        5         -     cli:root
```

**This one refuses while a hub is running**, and points at the REST API:

```console
$ cloop hub quota set alice@example.com --limit daily_cost_usd=5 --reason "runaway plan"
Error: a hub is running here and holds the control-plane lease: hub-1 (cloop-0 pid 812)

This command writes state that hub loaded into memory at startup, so a
write now would neither take effect nor survive its next edit. Use PUT
/api/quotas/{identity} or the Quotas panel while it is running, or stop it first.
```

That is not a limitation to work around. The enforcer reads overrides once at
startup, so a write behind a live hub would be invisible to it *and* would be
overwritten by the next edit made from the panel. Use the Quotas panel, or:

```bash
curl -X PUT https://hub.example.com/api/quotas/alice@example.com \
  -H "Authorization: Bearer $CLOOP_PAT" \
  -H 'Content-Type: application/json' \
  -d '{"limits":{"daily_cost_usd":5,"max_concurrent_tasks":2}}'
```

#### An admin is compromised

This is the one that had no answer before. Admin status comes from
`oidc.admin_emails` and `oidc.role_mappings`, which are read at startup — so
demoting somebody used to mean editing config and redeploying, with whoever
holds the deployment pipeline in the loop.

`cloop hub role revoke` writes a **deny binding** into the control-plane
database instead. It outranks every other binding at every specificity,
including the global admin binding `oidc.admin_emails` produces, and a running
hub picks it up within ten seconds without a restart.

```bash
# 1. Confirm where their authority comes from. This shows both layers: the
#    runtime bindings and the configured ones they override.
cloop hub role list --identity alice@example.com

# 2. Demote. This works while the hub is running.
cloop hub role revoke email alice@example.com --reason "credential compromise INC-4412"

# 3. A deny stops them acting. It does not end sessions or revoke tokens.
cloop hub session revoke --identity alice@example.com --reason "credential compromise INC-4412"
cloop hub token list        # then revoke anything the account holds
cloop hub token revoke <token-id>

# 4. Rotate anything they could have read: cloop hub key rotate, plus the
#    credentials behind any grant they could reach.

# 5. When the investigation closes, remove the binding by id. Deleting a deny
#    restores whatever remains in force — usually the configured policy, which
#    for an admin_emails entry means restoring admin. Do it deliberately, and
#    check `role list --identity` first: if a runtime grant for the same scope
#    is also stored, that grant takes over instead of the configured policy.
cloop hub role delete rb_e1be642bd28f --reason "investigation closed, account clean"
```

```console
$ cloop hub role revoke email alice@example.com --reason "credential compromise INC-4412"
DENIED email=alice@example.com (everywhere)
  binding  rb_e1be642bd28f
  This outranks every other binding, including oidc.admin_emails.
  Undo with `cloop hub role delete rb_e1be642bd28f`.

A deny stops them acting; it does not end their sessions or revoke their
tokens. For a compromise, also run:
  cloop hub session revoke --identity alice@example.com --reason "..."
  cloop hub token list   # then revoke anything they hold

A running hub picks this up within 10s. No restart needed.

$ cloop hub role list --identity alice@example.com
Runtime bindings (this database)
  ID               EFFECT  CLAIM  VALUE              ROLE  SCOPE     BY        REASON
  rb_e1be642bd28f  deny    email  alice@example.com  -     (global)  cli:root  credential compromise INC-4412

Configured bindings (.cloop/config.yaml)
  SOURCE        CLAIM  VALUE              ROLE   SCOPE
  admin_emails  email  alice@example.com  admin  (global)

alice@example.com is DENIED by rb_e1be642bd28f (everywhere) — every request resolves to no permissions.
```

**How long containment takes.** Three windows, and they are additive in the
worst case:

| | Bound | Why |
|---|---|---|
| REST and page loads | 10s | the binding TTL — bindings are re-read from the database on that interval |
| Open WebSocket or SSE stream | +30s | the writer loop re-checks the deny on its keepalive tick and closes the connection |
| Revoked session | 30s | the hub's per-process session cache |

So a demoted account stops being able to *act* within about ten seconds and
stops *receiving* within about forty. If you need both at zero, stop the hub —
which is also what you would do if you suspected the process itself.

**Precedence, in full.** Two rules, and nothing else:

1. **Deny wins.** An applicable deny binding denies outright, whatever else
   matches and at whatever specificity.
2. **The database overrides config.** If any runtime binding applies, the
   configured bindings are not consulted at all.

Both are needed for step 2 above to work: rank a deny against a tier-0 admin
binding and it loses; consult config after a runtime match and the admin binding
comes back.

**Scope it when you mean to.** With neither flag the deny is global. With
`--project` it withdraws authority on one project and leaves the rest intact:

```bash
cloop hub role revoke email contractor@example.com --project payments --reason "scope reduction"
```

**Other claims work too**, which matters when the provider releases no email:

```bash
cloop hub role revoke sub 8f14e45fce      --reason "offboarded, IdP entry not yet removed"
cloop hub role revoke group contractors   --reason "vendor breach, containing the whole group"
```

`cloop hub role grant` is the same mechanism in the other direction — a runtime
grant overrides the configured bindings, so it is also how you narrow somebody
(`--role viewer`) or widen them for one project, without a redeploy. It does not
beat a deny, and it is *not* the way to undo one: granting over a live deny
stores an inert row. The command says so, and `role delete` is the undo.

A binding cannot be narrowed to a project and an executor at the same time. No
request carries both — an executor action is a fleet action and deliberately
resolves with no project — so such a binding would match nothing. The command
refuses it rather than storing a deny that withdraws nothing.

Runtime bindings are policy that no reviewed file records, so a hub that has any
says so at startup:

```
RBAC: 2 role mapping(s), default role "none", plus 1 runtime binding(s) (1 deny) — see `cloop hub role list`
```

Treat that line as a reminder to clean up: a deny from a closed incident that
nobody removed is an account somebody thinks still works.

---

**A credential leaked.**
`cloop secret revoke <grant-id>` — then remember that material already
materialised survives up to 15 minutes, so stop the affected runs too. Rotate the
credential at its source. `cloop audit-log list --entity secret --since 7d` shows
who granted what and when. For egress, `cloop egress revoke` is immediate: live
sessions are torn down mid-tunnel.

**An executor is compromised.**
`cloop executor revoke <agent-id>` (cascades to the credential; the agent is told
not to reconnect), then `cloop executor cordon` any peer that shared its grants.
Audit-log `--entity executor` for what it was given. Assume every secret ever
leased to it is disclosed and rotate accordingly.

**`cloop audit-log verify` exits 2.**
Do not vacuum or maintain — that rewrites pages. Snapshot the file, `cloop db
verify` to separate corruption from tampering, and compare against your last
off-box export to find where the histories diverge.

**`/readyz` fails but `/healthz` passes.**
Read the `check` field first — it names which gate failed.

`"check": "sqlite"` is storage. Check the volume is mounted and writable, then
`cloop db verify`. Under Kubernetes, check the PVC is bound and that no second
replica is mounting it — SQLite is `ReadWriteOnce` and the chart pins
`replicaCount: 1` for that reason.

`"check": "identity"` means the hub has never resolved its OIDC issuer, so
nobody can sign in. The `error` field names the URL that was contacted and the
HTTP status it returned, and `remediation` says what to change. Run
`cloop hub doctor` from the same host for the full diagnosis — it performs the
same two round trips and prints the resolved authorization, token and JWKS
endpoints, which is the fastest way to tell a wrong realm path from a
certificate the hub does not trust. The gate clears on its own once the
provider answers, including via an ordinary sign-in; no restart is needed.

**The hub exits with "another cloop hub already controls this state".**
Not a bug — a second hub was started against a control plane that already has
one, and it refused rather than diverging. See
[the control-plane lease](#the-control-plane-lease).

**The hub logs "standing down" and exits after running normally.**
It lost its lease: something else took over the control plane while this process
was unable to renew for a full TTL, usually a long pause (a suspended node, a
stalled volume) or a second hub that judged it dead. The process is right to
exit — past that point another hub owns the state. Find the other hub with
`cloop hub lease status` and decide which one should be running.

`"check": "executors"` means the hub has nothing to dispatch to: strict mode is
on and no isolating executor registered. The `remediation` field says what to
do. The usual causes, in order of frequency:

- the config enables no isolating backend at all — set
  `executors.container.enabled` or `executors.kubernetes.enabled`, or enroll an
  edge device;
- one is enabled but could not be *built* — no container runtime on the hub
  host, or no kubeconfig grant. `GET /api/executors` carries a `reconciliation`
  block with a per-driver `status` and `remediation`, and the startup log has
  the same line;
- the hub is running in a distroless image (as the chart's is) with
  `executors.container.enabled: true`. There is no container runtime inside
  that image; use the Kubernetes backend, which is what
  `executor.kubernetes.enabled` in `values.yaml` configures.

Do **not** set `allow_host_process: true` to clear this. That does make the
probe pass, by removing the isolation boundary the gate exists to enforce.

**A sandbox cannot reach something it should.**
Work down the layers; each step rules one out.

1. **Ask the filter.** `--check` reports the verdict and the rule that decided
   it, and puts the verdict in the exit status (0 allow, 1 drop) so it composes
   into a script. Give it the *address*, not a name — a packet filter matches
   addresses:

   ```console
   $ cloop egress firewall --cidrs 10.8.0.0/24 --ports 6443 --check 10.8.0.5:22
   DROP  10.8.0.5 10.8.0.5:22/tcp — private (RFC1918/ULA)
   ```

   Reading the reason matters: `private (RFC1918/ULA)` means the address was
   inside the granted range but the *port* was not, so the waiver did not apply
   and the block set caught it. `default deny` means nothing matched at all.
   Use the same flags the executor is configured with, or `--grant <id>` to
   compile a stored grant. See
   [`cloop egress firewall`](../reference/commands.md#cloop-egress-firewall).

2. **Check that DNS is allowed — this is the most common cause by a wide
   margin.** A `filtered` policy with no `resolvers` drops UDP/53 along with
   everything else it does not name, and the symptom is not "DNS is denied", it
   is every connection failing at name resolution, which reads exactly like a
   network outage. The compiler warns about it at compile time:

   ```console
   $ cloop egress firewall --internet --ports 443 --format rules | grep -m1 resolver
   warning: no resolver is allowed, so DNS will fail: name lookups leave the sandbox on UDP/53 and this policy drops them. Pass the sandbox's resolvers, or use the broker, which resolves on its behalf.
   ```

   The fix is to name the sandbox's resolvers in
   `executors.container.egress_filter.resolvers`, or to route the sandbox
   through the broker, which resolves on its behalf. On Kubernetes, check that
   `allow_cluster_dns` has not been set to `false`. Resolvers are opened on TCP
   as well as UDP, because a truncated answer retries over TCP and a
   UDP-only resolver fails on large responses in a way that looks like a
   different bug.

3. **Look at the counters on the host.** Every rule carries one, so the ruleset
   shows what is actually being dropped rather than what should be:

   ```bash
   nft list table inet cloop_sbx_<executor-id>
   ```

   The table name is `cloop_sbx_` plus the executor id lower-cased, with every
   character outside `[a-z0-9]` replaced by `_`. A non-zero counter on a `drop`
   rule names the destination range and the reason; a zero counter on the
   `default deny` line means the traffic never arrived, which points upstream —
   at routing, at the image, or at the workload not trying.

   There is **no table for an `internal: true` filter**, and that is not a
   fault: that form installs no rules at all, because the runtime puts no route
   off the bridge in the first place. If `nft list table` says the table does
   not exist, check which form the executor is configured with before
   concluding the filter failed to install — and note that a failed install
   fails the `Start`, so a running sandbox is never one whose rules went
   missing.

4. **Re-run preflight.** `cloop executor test <executor-id>` is the command
   that surfaces the driver's `egress` finding — what the filter will enforce,
   or that it is not filtering at all — plus a separate `egress-scope` finding
   for anything the filter is wider than its grant. Exit 2 means preflight
   found a fatal problem and no workload was attempted; the usual ones are
   `nft(8)` missing or the control plane lacking `CAP_NET_ADMIN`, both `fail`,
   both with the fix in the message, and both avoidable by switching the filter
   to `internal: true`, which needs neither. `cloop hub doctor` does not repeat
   these findings — its `executors` group reports reconciliation, the
   strict-mode gate and a liveness probe.

5. **On Kubernetes, confirm the CNI implements NetworkPolicy.** cloop creates
   the object and the API server stores it whether or not anything enforces it,
   so a cluster running flannel looks identical to a working one from the hub's
   side — and the failure is the opposite of this playbook's: traffic that
   should be *blocked* is not. `kubectl get netpol -n <ns> -o yaml` shows what
   was created; only the CNI's own documentation says whether it is honoured.

If the destination is one the sandbox should reach through the **proxy** rather
than directly, this is the wrong tool: `cloop egress test <url>` asks the
layer-7 question, and a host allowlist is only ever enforced there.

**"database is locked".**
WAL and `busy_timeout` are already configured, so this points at a second writer.
Check for a stray `cloop` process on the same `.cloop` directory, or a shared
volume.

**Nothing will schedule.**
Read the placement error: it names the constraint and lists per-candidate
rejections. `host_policy` means strict mode refused the only available executor —
correct behaviour, wrong fleet. Bind the project to an isolated executor or
enable the container backend; do **not** set `allow_host_process: true` to make
the message go away.

**A project shows "running" but nothing is running.**
This resolves itself. A run that is killed rather than stopped — the kernel's
OOM killer, a `SIGKILL`, a host reboot — never writes a terminal status, and the
hub reconciles that within a few seconds: the project returns to `paused`, each
task the run left in progress is either adopted (its agent had finished and said
so, so the outcome is taken rather than the work redone) or re-queued, and the
event journal records why. Look there first: the entry names the cause,
and an out-of-memory kill says so explicitly along with the remedy (give the
executor more memory, or make the task hold less at once). Repeated OOM entries
for the same project are a sizing problem, not a cloop problem.

If it does *not* resolve, the hub is telling you it refused to. Check the server
log for `stale-run recovery: skipped, state points at another directory` — that
is a project whose `.cloop` was copied or moved from somewhere else, so its
persisted `WorkDir` names its old home and writing the repair would land in the
original project's database. Fix the state file rather than the symptom.

**Restarting the hub does not stop the runs it started.**
This is deliberate, and it is why the nightly rebuild of `cloop-latest` does not
interrupt work in progress. Runs are orphaned rather than killed
(`KillMode=process` on both hub units) and they are built to outlive the hub: a
run whose output pipe breaks keeps working and still records its outcome, so
losing the hub costs the live-log stream and nothing else. Progress keeps landing
in `state.db`, so the task list stays current even while the log panel is empty;
streaming resumes with the *next* run, not the one that was in flight.

Before this, such a run died — not of the kill, but of its own next log line,
because Go makes `SIGPIPE` fatal on file descriptors 1 and 2. That committed the
work and lost the outcome, which was the most common way a project came to be
stuck showing "running" at all. If you want a run to stop, stop it: the Stop
button, or `POST /api/projects/{idx}/stop`.

---

## See also

- [Executor architecture](../architecture/executors.md) — health, cordon, failover
- [Security model](../security/model.md) — what the boundaries authenticate with
- [Threat model](../security/threat-model.md) — deployment-level threats
- [Secret and egress grants](../guides/secrets.md) — grant and revoke procedures
- [Kata Containers](../guides/kata.md) — VM-isolated sandboxes: setup and verification
- `deploy/README.md` — image, compose stack and Helm chart specifics
