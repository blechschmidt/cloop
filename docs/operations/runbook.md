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
| `/readyz` | should traffic come here? | two gates: the state database, then the execution path. Fails during startup, on storage loss, and when strict mode leaves no isolating executor registered |
| `/metrics` | Prometheus text | — |

All three bypass auth and rate limiting so a probe can never be locked out by a
flood or a broken IdP.

The second `/readyz` gate is why a rollout of a misconfigured hub fails instead
of going green. A hub with `allow_host_process: false` and no container,
Kubernetes or enrolled-agent executor can only answer a run request with a 409,
so it reports `not_ready` and the response body names the fix:

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
| `storage` | `quick_check`, and the schema version against this binary's — the rollback case |
| `quotas`, `budget` | policy validity, limits set to `0` (which means *none allowed*, not unlimited), and unbounded spend on a multi-tenant hub |

Exit is 1 on any failure and 0 with only warnings, so it is usable as a
deployment gate. `--strict` fails on warnings too. Every non-pass finding
carries a one-line remediation; the `check` ids in `--json` are stable.

Run it twice: once before the first `helm install` or `docker compose up`, and
once in CI against the config repo. `--offline` makes the second cheap.

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

`--verify` refuses to export a broken chain, so an exported file is one that
passed verification at export time. Every format carries `prev_hash` and
`row_hash`, letting the recipient re-verify independently. Filters: `--actor`,
`--entity`, `--entity-id`, `--type`, `--since`, `--until`, `--limit`. Output files
are written 0600.

Audit rows never contain credential material — that is asserted by
[five separate checks](../security/model.md#secret-non-disclosure--secrets_testgo-audit_testgo),
including one that scans *every* row rendering rather than a sample.

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

Schema migrations live in `pkg/statedb/migrations/` (`0001_init.sql` through
`0019_envelope_encryption.sql`), are embedded in the binary, and are applied
automatically by `statedb.Open()` on every start. Each runs in a transaction and
records itself in `schema_migrations`, so a crash mid-migration rolls back
cleanly and the next start retries.

**There are no down-migrations. Migration is roll-forward only** — which is why
step 1 below is not optional.

```console
$ cloop db backup                        # 1. NOT optional — the only way back
$ cloop migrate --dry-run                # 2. what would change
$ cloop --version                        # 3. install the new binary
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

**A newer schema cannot be opened by an older binary**, and there are no
down-migrations. Rollback is therefore *restore*, not *downgrade*:

1. stop the hub
2. install the previous binary or image tag
3. `cloop db restore <backup taken before the upgrade> --force`
4. `cloop db verify`
5. start; check `/readyz`, then `cloop audit-log verify`

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

Taking a node out of service:

```console
$ cloop executor cordon edge-01 --reason "kernel patch"   # no new work; running work continues
$ cloop executor drain  edge-01 --reason "decommission"   # no new work; wait for zero in-flight
$ cloop executor uncordon edge-01                          # back to whatever the probes justify
```

`uncordon` does not optimistically mark the node ready — it returns it to the
state its probes justify.

If a node dies rather than draining, the supervisor does it for you: three missed
heartbeats (~45 s) mark it `unreachable` and in-flight sessions are re-placed on
surviving nodes exactly once. See
[failover](../architecture/executors.md#failover-task-20162).

```console
$ cloop executor reap                    # remove sandbox containers/Pods left by earlier runs
```

---

## Incident playbooks

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

---

## See also

- [Executor architecture](../architecture/executors.md) — health, cordon, failover
- [Security model](../security/model.md) — what the boundaries authenticate with
- [Threat model](../security/threat-model.md) — deployment-level threats
- [Secret and egress grants](../guides/secrets.md) — grant and revoke procedures
- `deploy/README.md` — image, compose stack and Helm chart specifics
