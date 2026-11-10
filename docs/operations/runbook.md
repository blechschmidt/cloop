# Operator runbook

Backup, escrow and restore, audit verification, key rotation, upgrade and
rollback for a hosted cloop hub.

The command output on this page is real. Where a step can't be undone (a lost
key, a one-way migration), the warning is next to that step.

- [Layout](#layout)
- [Health checks](#health-checks)
- [Backup and restore](#backup-and-restore)
- [Database maintenance](#database-maintenance)
- [Audit chain verification](#audit-chain-verification)
- [The git interception proxy](#the-git-interception-proxy)
- [The Kubernetes access monitor](#the-kubernetes-access-monitor)
- [Key rotation](#key-rotation)
- [The root key](#the-root-key)
- [Upgrade](#upgrade)
- [Rollback](#rollback)
- [Fleet operations](#fleet-operations)
- [Incident playbooks](#incident-playbooks)

---

## Layout

```
cloop-secret-key                 0600     CLOOP_SECRET_KEY, beside .cloop/ and never in it
                                          (cloop-secret-key.cred when systemd-creds sealed it)
.cloop/
  state.db                                canonical store (SQLite, WAL mode)
  state.db-wal  state.db-shm              WAL sidecars — never copy these by hand
  config.yaml                    0600     operator-written; safe to commit
  hub.env                        0600     CLOOP_UI_TOKEN — never commit
  tls/cert.pem  tls/key.pem      0600     when the hub terminates TLS itself
  backups/state-<UTC>.db                  + a .db.meta.json sidecar per backup
```

A hub bootstrapped by a release before v0.0.6 keeps `CLOOP_SECRET_KEY` in
`hub.env` instead. That still works, and [the root key](#the-root-key) explains
how to move it.

Two rules prevent most problems:

1. **The root key opens every sealed secret.** Back it up separately from
   `state.db`, never in the same place: a backup that holds both is effectively
   a plaintext secret store. For the same reason the hub refuses to read a key
   file from inside a `.cloop/` directory, because backups, snapshots and seeded
   sandboxes all carry that directory.
2. **Never copy `state.db` with `cp`.** Use `cloop db backup`. It writes a
   single self-contained file that doesn't depend on the `-wal`/`-shm` files.

---

## Health checks

| Endpoint | Question | Behaviour |
| --- | --- | --- |
| `/healthz` | is the process alive? | Never fails while the process can accept a connection. Do **not** restart the hub when the database is slow. |
| `/readyz` | should traffic come here? | Three gates, in order: the state database, the identity provider, the execution path. Fails during startup, when storage is lost, while the issuer has never resolved, and when strict mode leaves no isolating executor registered. |
| `/metrics` | Prometheus text | Requires the `audit.read` permission, unlike the two probes above. |
| `/api/hub/health` | will it keep working? | `cloop hub doctor`'s checks. Each serving hub member runs them on itself every five minutes (`ui.hub_health_interval`) and whenever something they check changes. Requires `config.write`. Shown in Settings → Hub health; see [Hub health in the dashboard](#hub-health-in-the-dashboard). |

`/healthz` and `/readyz` skip authentication and rate limiting, so a flood of
requests or a broken IdP can't lock out a probe. `/metrics` is an ordinary
authorised route, so a scraper needs a credential with `audit.read`. See
[Metrics](metrics.md).

Because of the second and third gates, rolling out a misconfigured hub fails
the rollout. It doesn't go green.

The identity gate catches a hub pointed at an issuer that is unreachable,
misspelled or wrongly registered. Without it, such a hub would come up green
and fail for the first person who tried to sign in. The hub resolves the issuer
at startup (discovery and the JWKS fetch) and reports `not_ready` with
`"check": "identity"` for as long as that has *never* succeeded. After one
success the gate stays open: existing sessions keep working through a later
provider outage, and taking the hub out of its Service during one would turn a
login outage into a total outage. To make the hub refuse to start instead, set
`ui.oidc.require_idp` (or pass `cloop ui --require-idp`).

The execution gate checks that runs have somewhere to go. A hub with
`allow_host_process: false` and no container, Kubernetes or enrolled-agent
executor can only answer a run request with a 409, so it reports `not_ready`,
and the response body says how to fix it:

```json
{
  "status": "not_ready",
  "check": "executors",
  "reason": "strict mode is on (executors.allow_host_process: false) and no isolating executor is registered, so every run would be refused",
  "remediation": "enable executors.container or executors.kubernetes in .cloop/config.yaml, enroll a remote agent (`cloop executor enroll`), or set executors.allow_host_process: true to permit un-isolated host execution"
}
```

The check is live. A hub that starts with no isolating executor becomes ready
as soon as an edge device enrolls, without a restart. An executor that
registered but failed *preflight* counts as degraded, not missing, and still
satisfies this gate: a cluster that was briefly unreachable while the hub
started shouldn't keep the hub out of service until someone restarts it.

```console
$ cloop hub healthcheck --url https://hub.example.com --endpoint readyz
$ kubectl -n cloop exec deploy/cloop-cloop-hub -- /usr/local/bin/cloop hub healthcheck --endpoint readyz
```

The image is distroless, with no shell and no `curl`, so this command is the
container's `HEALTHCHECK` and the Kubernetes exec probe. Options: `--timeout`
(default 3 s) and `--ca-file` for a private CA. It exits 0 when healthy and 1
otherwise.

### Configuration health: `cloop hub doctor`

`healthcheck` tells you whether the hub is up. `doctor` tells you whether it is
configured to keep working. A hub whose certificate expires next week, whose
issuer moved, or whose RBAC policy leaves nobody an admin passes both probes
and is still broken.

```console
$ cloop hub doctor                    # in the hub's directory
$ cloop hub doctor --json | jq '.findings[] | select(.severity=="fail")'
$ cloop hub doctor --offline          # config only; contacts nothing
$ cloop hub doctor --port 8081        # the hub on :8081, with its overlay
```

When two dashboards share a directory, each one reads its hub-scope settings
from its own `.cloop/config.ui-<port>.yaml`, merged over `config.yaml`. Pass
`--port` to check one of them as it runs. The default is 8080, the port
`cloop ui` uses without `--port`, so `cloop hub doctor` with no flags checks
the hub that `cloop ui` with no flags starts. `--port 0` reads `config.yaml`
alone. In every case the report lists on stderr any overlay it did not merge.
See [two dashboards in one directory](../reference/configuration.md#two-dashboards-in-one-directory).

Each check calls the same code the hub runs instead of keeping a copy of its
rules. Whether `cloop ui` would start with `ui.oidc` is decided by
`oidcauth.New`. Whether a redirect path can be served is decided by the rule the
router is built from. Whether the git proxy starts is decided by `tlsconf`
loading its key pair and `gitproxy.NormalizeBaseURL` checking its base URL, and
so on. A doctor with its own copies of the rules could fail a working hub (one
that registered its callback at `/auth/oidc`, which the hub serves, was told
the hub "only serves the callback at /auth/callback") and pass a broken one.

The checks, and what each one catches that nothing else does:

| Group | Checks |
| --- | --- |
| <a id="doctor-policy"></a>`policy` | Whether `executors.allow_host_process` was set explicitly or only left at its default. `executors.host_sandbox`: **fail** when single sign-on is on, runs may fork on the hub's host and the [host sandbox](../security/model.md#the-host-sandbox) is off, because then every person's agent can read every other person's projects and Claude login; **fail** too when the host cannot give the sandbox (no Landlock ABI 3), so the hub refuses the runs that need it; **warn** when `executors.host_sandbox.read_only` names a path the hub leaves out because it would expose the hub's files or other people's, and on a hub running as root below Landlock ABI 6, where a sandboxed run can still reach the host daemons' abstract sockets. |
| <a id="doctor-oidc"></a>`oidc` | Whether `cloop ui` would start with `ui.oidc` (`oidc.startup`, decided by `oidcauth.New`, the constructor startup runs). The redirect URI: its path is checked by the hub's own rule, so any path under `/auth/` that the router can serve passes (an Entra SPA registration commonly uses `/auth/oidc`), and only a path the hub refuses fails, saying the hub will not start. Its origin is checked against `ui.external_url`. Issuer discovery, the issuer name in the discovery document, and JWKS keys cloop can actually verify with. Whether the client secret comes from the environment and not the committed config. Whether privileged actions require a recent sign-in (`oidc.sudo`): **warn** while `ui.oidc.sudo_max_age_minutes` is `-1`, because a stolen session cookie can then mint tokens and grant secrets until it expires. In Settings → Hub health, the issuer the hub signs in with is read from its sign-in client, not resolved again: `oidc.discovery` and `oidc.jwks` report when the client resolved the issuer and fetched its keys, and why its last fetch failed, with a **warn** for a key-set refresh that failed while the client still holds keys. `oidc.running` **warns**, until a restart, that the configured issuer is not the one this process signs in with. |
| <a id="doctor-tls"></a>`tls` | The certificate and key load as a matching pair, the same way the listener loads them (`tlsconf`). The chain the listener presents is in order and parses. Expiry (warns 30 days ahead). The SANs cover the external hostname. Key file permissions. TLS terminated at a proxy, judged by the rule an edge agent applies to `ui.external_url`. |
| <a id="doctor-ui"></a>`ui` | `ui.exposure`: where the process on `--port` actually listens (read from the kernel's socket table), and whether it answers `GET /api/projects` without credentials. **Fail** if a hub without sign-in can be reached from beyond loopback, or would be after a restart (a `ui.listen` beyond loopback together with `ui.allow_unauthenticated_network`, or a setting `cloop ui` refuses to start with). This applies whichever build serves the port, so it also catches binaries built before loopback became the default. **Warn** if a hub with sign-in serves plaintext beyond loopback while its public URL (`ui.external_url`, else `ui.oidc.redirect_url`) is https. With nothing on the port, it judges what `cloop ui --port N` would do; if the hub uses `CLOOP_UI_TOKEN`, export it from `hub.env` first. `ui.static_token`: **warn** while a static token is accepted (exported in the doctor's shell, or reported by a running hub) alongside single sign-on with an enforced role policy, saying how long the token has gone unused; **pass** once it is retired. Reports nothing without SSO, where the token is the sign-in, or without a role policy, where `rbac.enforced` is the finding. |
| <a id="doctor-secret_key"></a>`secret_key` | Where the root key comes from (`secret_key.source`): a source the hub would refuse fails; an environment variable on a host that systemd runs, or a copy of a key file's key left in the environment, warns. That `CLOOP_SECRET_KEY` is present and is generated key material, not a passphrase or a placeholder copied from the docs; for a weak key the finding tells you to change the root, not to rotate. Whether the key opens this hub's sealing keys, asked read-only of the keyring the broker opens (`secret_key.matches`): a live key that no configured root derives fails, because the hub would not start. A warning for as long as `CLOOP_SECRET_KEY_PREVIOUS` is set (`secret_key.previous`). The escrow on record (`secret_key.escrow`). With a KMS among the roots: its configuration (`secrets.kms.config`); whether each KMS answers and how fast (`secrets.kms.reachable`, a failure for one that does not); a change of root still in progress (`secrets.kms.previous`); and keys still wrapped under a KMS key version the KMS no longer encrypts under (`secrets.kms.rewrap`). |
| <a id="doctor-rbac"></a>`rbac` | Whether a role policy is in force at all (`rbac.enforced`, from `authz.Enforced`, the same answer the request gate acts on). It fails, naming the issuer, for single sign-on with no `role_mappings` and no `default_role`: every identity the issuer authenticates then holds every permission except executor administration. See [when RBAC is in force](../security/model.md#when-rbac-is-in-force). That the mappings parse. How much the default role allows, reported only where a policy makes that meaningful. Group bindings without the `groups` scope. Whether anybody maps to admin. All of these are judged on the policy as `authz` normalizes it, so `role: Admin` is admin, and a project-scoped admin is not a hub admin. Where a policy is in force, every live API token it suspends: tokens with no owner, minted while no policy was in force or before the hub recorded how, and not approved since (`api_tokens.unapproved`, a failure naming each). Approve the ones you can vouch for and revoke the rest. |
| <a id="doctor-scim"></a>`scim` | Whether `cloop ui` would start with `ui.oidc.scim` (`scim.config`). Whether the directory the identity provider provisioned can reach the people in it (`scim.directory`): when the provider deactivates a provisioned user with no value for `match_claim`, the hub has nobody to refuse, and two users sharing one value get no guess and neither user's groups. See [SCIM provisioning](#scim-provisioning). |
| <a id="doctor-offboard"></a>`offboard` | Whether the Claude Code home of an identity the control plane denies (an offboarded or deactivated user) is still on this host (`offboard.claude_homes`). It holds that person's refresh token in plaintext. Running members remove such homes from their own trees at startup and every hour, so a copy found here belongs to a stopped member, or is one a sweep could not remove. |
| <a id="doctor-images"></a>`images` | Whether the policy is valid, and whether it constrains registries at all (asked of the policy's own evaluation). Digest pinning. Whether cosign is installed and its keys are readable wherever signatures are verified: the container and Kubernetes executors, and the hub itself for a device or virtual executor whose sandbox runs a container. The operator's own executor images, which are exempt from the policy unless `govern_operator_images` is set, and are reported as exempt. Whether the registries the policy names can be reached. A device fleet and a Kubernetes executor need them from the hub too: the hub resolves a device's tag there before verifying it, and resolves every tag a Pod would carry before building the Pod (`cloop executor test kubernetes` adds the `registry-login` and `image-resolution` checks). `images.provenance`: whether cosign is on the hub's `PATH`, and its version (read from the binary's build information, without running it); `executors.image_provenance`; and what each of cloop's own images in use resolved to: verified, unsigned or unverifiable (a warning, or a failure under `required`), or wrongly signed (a failure). `cloop hub doctor` verifies the images as the next dispatch would; Settings → Hub health reports what the hub's dispatches found. |
| <a id="doctor-executors"></a>`executors` | Reconciliation diagnostics, the strict-mode gate (asked of the same check `/readyz` serves), and a liveness probe and capability report for each executor. Each device on the edge channel, compared with this build's place on `main` (`executors.edge_lag`): a warning when it is more than 20 sequences behind, or when its build carries no sequence, which rollback protection does not cover yet. Each device that follows releases with a build that carries no sequence (every release before v0.0.5), with how to cover it (`executors.rollback_protection`). Each executor's isolation claim, compared with what the isolation probe found under its runtime (`executors.isolation`): a failure for a runtime named for isolation that provides less (a `kata` that is really runc), where projects that require isolation are refused; a warning for a claim never verified, or for evidence older than two days. Each live executor pool, from its queue, its runners and what its controllers last told the hub (`executors.pools`): a **failure** when runs wait and no controller is in contact, because the pool has no live credential, none was ever used, or none was used in ten minutes (`executors.pools.contact`); a warning when a run has waited ten minutes while the pool has every runner its `max_runners` allows, while it has room for more that its controller does not start (often an ExecutorPool `spec.maxRunners` lower than the hub's), or while it is cordoned (`executors.pools.capacity`); when its controller reports runner volumes stuck Pending or other trouble starting runners (`executors.pools.storage`); and when a controller used in the last day speaks an older pool-controller protocol than this hub (`executors.pools.protocol`). The Executors tab's pool cards and `cloop executor pool list` show the same problems. |
| <a id="doctor-runs"></a>`runs` | The build each `cloop run` on this host executes, compared with the hub's (`runs.build_lag`). It reports a run that is behind (a host-process run can adopt the newer build at its next task boundary) and a run that recorded no build (it has to be restarted once before it can). See [Long-lived runs after an upgrade](#long-lived-runs-after-an-upgrade). Every adopted run whose hub process could not take over a credential yet (`runs.lease_takeovers`): a **warning** for each lease, workspace lease or egress session the run's owner row lists as undecided. The warning says since when, how many attempts, why, until when it will be retried, and whether the member that owns the run still serves. It reads the run claims, so it works with no member running. See [A takeover the store cannot decide](#after-a-control-plane-restart). |
| <a id="doctor-gitproxy"></a>`gitproxy` | Whether pushes are brokered at all. Whether the proxy would start: its TLS material loaded the way the listener loads it, and its base URL checked by `gitproxy.NormalizeBaseURL`. The base URL sandboxes are pointed at (`advertise_url`, or the bound address as the hub advertises it), whether only this machine can reach it, and a bounded dial of it. The branch allowlist and delete authority. With the proxy off, any GitHub grant whose branch list therefore cannot be enforced (`gitproxy.branch_grants`). Under `tls: auto`, the certificate the hub issued the proxy (readable, verifies against the hub CA, names the advertised host, not about to lapse) and the hub CA's expiry (`hubca.expiry`; see `hubca` below). |
| <a id="doctor-hubca"></a>`hubca` | The hub's own CA under `tls: auto`. Its expiry (`hubca.expiry`): a warning within a year and a failure within 30 days, naming the rotation. A rotation in progress (`hubca.rotation`): a stage older than the longest `session_minutes` a monitor grants (the runs it waits for should have ended by then), a previous CA still trusted that long after its activation, and a failure when the leader has not reissued the certificates minutes after an activation. Whether every live member takes part (`hubca.members`): a member on a build that predates rotation, which an activation refuses to run alongside, or a member that has fallen behind. The active CA's name constraints, compared with the names the monitors are configured at (`hubca.names`, a failure for a name the constraints do not permit). See [Rotating the hub CA](#rotating-the-hub-ca). |
| <a id="doctor-kubeguard"></a>`kubeguard` | Whether kubeconfig grants are brokered at all. Whether the monitor would start: its TLS material and CA bundle read the way the hub reads them, and its base URL checked by `kubeguard.NormalizeBaseURL`. Where sandboxes are pointed, whether only this machine can reach it, and a bounded dial. The verb ceiling. Under `tls: auto`, the hub-issued certificate and the hub CA, as for the git proxy. |
| <a id="doctor-egress"></a>`egress` | Whether the broker is on. For each running hub, where its proxy listens and is advertised, or why it would not bind (`egress.hosted`, read from the status every hub records at startup). How each kind of sandbox this hub runs reaches the proxy, by the hub's own routing rules: containers by the bind address (`egress.listen_addr`), Pods and devices by `advertise_addr` (`egress.advertise_addr`), with a bounded dial of it. An `internal: true` filter with no broker to proxy through, which leaves the sandbox no way out. |
| <a id="doctor-knowledge"></a>`knowledge` | Whether semantic knowledge search sends anything out of the hub (`knowledge.embeddings`). It passes when search is off. When it is on, there is always a finding naming the endpoint that receives the text of every chunk and every search query, with the model and how many chunks have a vector from it: a warning for plain `http` beyond loopback, and a **failure** for a section refused at load. Whether the key that `secret_ref` names can be presented (`knowledge.embeddings.secret`). The sources whose last sync could not embed (`knowledge.embeddings.sync`), quoting each one's warning. See [semantic knowledge search](../reference/configuration.md#semantic-knowledge-search-knowledgeembeddings). |
| <a id="doctor-firewall"></a>`firewall` | Whether any egress allowlist opens a cloud metadata service by including it (`firewall.metadata`). An `egress_filter` allowlist in force in `config.yaml` is a **fail** (`cloop ui` refuses to start with it), and one in a switched-off section is a warning. Every stored rule set or egress grant saved before the rule existed: the service stays closed, but the rule set should name or deny it. This covers the device, virtual-executor and project firewalls and the active grants, each reported by where it is and what it contains. |
| <a id="doctor-projects"></a>`projects` | Every registered project's directory, checked against what the hub must never bind into a sandbox (`projects.confinement`): the control plane, the projects root, another hub's directory or another project. A **fail** names each project the hub refuses to run and what it overlaps; a tree too large to search is a warning. Nothing is moved or deleted. |
| <a id="doctor-storage"></a>`storage` | `quick_check`. The schema version compared with this binary's, which catches a rollback: it names the build that moved the schema, and fails only where the hub's guard refuses the database (a database ahead only by additive migrations opens). Whether `CLOOP_ALLOW_SCHEMA_DOWNGRADE` is suppressing that guard. Free space on the volume holding `.cloop`, compared with `orchestrator.min_free_disk_mb` (`storage.free_space`): a warning below twice the floor and a failure below it; see [Disk space low](#disk-space-low). The write-ahead log beside `state.db` (`statedb.wal`, measured before any other check opens the database): a warning once it is larger than both 64 MiB and a quarter of the database; see [The write-ahead log](#the-write-ahead-log). |
| <a id="doctor-retention"></a>`retention` | Whether the janitor will run here at all (`retention.janitor`) and when it last ran (`retention.last_run`). What the row tables, the disk, the audit archive and plan history hold, compared with the retention policy (`retention.tables`, `retention.disk`, `retention.archive`, `retention.history`). The share of `state.db` that is free pages a `VACUUM` would give back (`retention.freelist`). |
| <a id="doctor-audit"></a>`audit` | Whether the control-plane chain records lost events (`audit.gaps`: its `audit.gap` rows and how many events they cover). Whether a hub process here still holds losses it has not recorded, or exited holding some (`audit.unrecorded`, read from the status files under `.cloop/audit-failures/`). The head checkpoints: whether they are written at all, to stderr only or to a file outside `.cloop/` (`audit.checkpoints`: a **fail** for a file that may not hold them, and a warning when the newest control-plane record is more than three intervals old); whether they are sealed or unsigned (`audit.checkpoints.signed`); and whether the newest 50 still agree with the chain (`audit.checkpoints.chain`: a **fail** naming a truncated tail or a restored backup). See [Audit chain verification](#audit-chain-verification). Whether the trail's content leaves the machine (`audit.forward`: no sink is a warning), whether each configured sink could start (`audit.forward.sink`), and whether it keeps up (`audit.forward.lag`: a sink that has never acknowledged a row while rows are waiting, or whose oldest waiting row is older than `audit.forward.max_lag`). See [Forwarding the trail off the box](#forwarding-the-trail-off-the-box). |
| <a id="doctor-config"></a>`config` | Every value that loading had to repair (`config.repaired`). A value reset to its default is a warning. A section switched off because it could not start as written is a failure; for the git proxy, the Kubernetes monitor and the egress proxy it is reported under the section's own check, which would otherwise read as "disabled". Drift between `.cloop/config.yaml` and the copy mirrored in `state.db`, the usual cause when you change a setting and nothing happens. |
| <a id="doctor-quotas"></a>`quotas`, `budget` | Whether the policy is valid. Limits set to `0`, which means *none allowed*, not unlimited (except `max_sessions`, where `0` means no cap). Both are judged as `quota.New` holds them, so a negative ceiling is unlimited. Unbounded spend on a multi-tenant hub, judged by the daily caps `budget.Enforce` holds a run to: the project's own caps, read from `config.yaml`, which is where runs read a budget. The host-wide caps in the doctor's `~/.config/cloop` are reported alongside them, because they only limit runs on the host's own driver (an isolated run doesn't get them). `monthly_usd` is never counted, because nothing enforces it. |

The exit status is 1 on any failure and 0 with only warnings, so you can use it
as a deployment gate. `--strict` fails on warnings too. Every finding that isn't
a pass comes with a one-line remediation, and the `check` ids in `--json` are
stable.

Three of the checks dial an address. `executors.git_proxy.advertise_url`,
`executors.kube_guard.advertise_url` and `executors.egress.advertise_addr` are
the only configuration values a hub hands to a sandbox and never uses itself,
so a value that works on the hub but can't be routed from a Pod shows up
nowhere else. The dial is bounded (3 s, or `--timeout`) and never fails the
run: the hub isn't on the sandbox's network, and for the git proxy and the
Kubernetes monitor a Service name that doesn't resolve on the hub is often the
*correct* setting. (The egress proxy is different: the hub refuses to give Pods
a cluster-internal name, and `egress.advertise_addr` fails on one.)
`gitproxy.advertise_reachable`, `kubeguard.advertise_reachable` and
`egress.advertise_reachable` tell "nothing is listening" apart from "this was
never checked". `--offline` reports them as skipped.

Run the doctor twice: once before the first `helm install` or
`docker compose up`, and once in CI against the config repository. With
`--offline` the CI run is cheap.

### Hub health in the dashboard

`cloop hub doctor` needs a shell on the hub host, in the hub's directory, with
both configuration files in reach. Administrators of a Helm or compose
deployment, or without shell access, don't have that. Settings → **Hub health**
runs the same checks inside the serving hub (`GET /api/hub/health`), and the
header tells administrators when a check fails:

- **Whose view.** The report uses the hub's own directory and the configuration
  that process runs under: `config.yaml` with its `config.ui-<port>.yaml`
  overlay merged, as `cloop hub doctor --port <its port>` would read them. It
  also uses the process's own environment, so the root key, the KMS and the
  static token are the hub's. The listener checks (`ui.exposure`) describe the
  process that answered, so the report names the cluster member, its host and
  its port. Behind a load balancer, each member answers with its own report.
- **What it does not do.** It doesn't run `--smoke` or
  `--probe-network-policy`, because both start work; the panel prints the
  command that runs them on the host. Where the doctor in a shell has to ask
  from outside, the hub answers from what it already knows. The executor checks
  read the drivers the hub reconciled at startup and what its executor
  supervisor last recorded about each one, without reconciling or probing again
  (every member reads the same record, and only an executor nobody has probed
  yet is asked, once). `ui.exposure` judges the listener by how the process
  admits requests, without sending it a request that has no credentials, which
  a token-only hub would count as a failed sign-in. The sealing-key checks use
  the KMS clients the hub pinned at startup, so a report never logs in to Vault.
  The issuer the hub signs in with is read from its own sign-in client: the
  discovery document and keys it holds, when it fetched them, and why its last
  fetch failed. A report about a resolved issuer therefore sends nothing to the
  identity provider, and a brief problem at the provider only becomes a finding
  when it affected the hub: a sign-in that could not begin, or a key set it
  could not refresh for a token that needed it. While the client has no usable
  resolution (it never resolved the issuer, holds no keys, or its last fetch
  failed), a report asks it to try again at most every 15 minutes, and **Run the
  checks again** at most every minute, so a failure that has cleared doesn't
  stay red until somebody signs in. The report resolves an issuer itself, at
  most every 15 minutes, only when the running process doesn't sign in with it
  (single sign-on was switched on, or the issuer changed, after the process
  started; `oidc.running` says so). The other network probes are the ones the
  checks already make (registries, the advertised proxy addresses), each
  bounded to 5 seconds.
- **When a check misbehaves.** Each check runs on its own goroutine with its
  own 20-second deadline, and its panics are recovered. A check that doesn't
  finish is reported as `doctor.unfinished`, with whatever it found before the
  deadline. A check that panics is reported as `doctor.panic`, with the stack
  trace in the hub's log (event `health_check`). The rest of the report is
  unaffected. A check that never returns isn't started again; until it returns,
  each report says it is still running. `cloop hub doctor` on the host runs the
  same check without a deadline, which shows where it stops.
- **How fresh.** Each member makes its own reports, one at a time. It makes one
  every five minutes (`ui.hub_health_interval`, between `1m` and `1h`; the
  setting is per process, so a member can set its own in its overlay). It also
  makes one within a few seconds of a change to either configuration file (from
  Settings, from another member, or an editor on the host), and soon after an
  event that changes what the checks find: an executor enrolled, lost or
  reconfigured, a step of a hub CA rotation, a sealing key rotated, retired,
  rewrapped or escrowed with `cloop hub key`, or the static token retired. A
  burst of events produces one report, never sooner than a minute after the
  previous one, and an event that arrives while a report is being made triggers
  the next one as well. Events from outside the member (another member's, and
  those of `cloop hub key`) arrive over the cluster bus. A hub started with
  `ui.cluster.exclusive` doesn't read the bus, so it sees them at its next
  scheduled report. Reads are answered from the latest report, so behind a load
  balancer the number of reports a member makes doesn't depend on how many
  dashboards are open. Seven checks are too expensive to repeat in every report.
  They run at most every 15 minutes, and the reports in between carry their
  last result with the time it was made: `storage.integrity` (`quick_check` and
  `foreign_key_check` read the whole database file), `retention` (it sums the
  largest tables' rows), `projects.confinement` (it walks every registered
  project's tree), `gitproxy`, `kubeguard` and `egress` (each dials the address
  sandboxes reach the monitor at, often this process's own listener, which logs
  the bare connection as a TLS handshake error), and resolving an issuer the
  process doesn't sign in with. If one of them overruns its deadline, its result
  is still kept when it finishes. **Run the checks again** reruns everything
  whose last run is more than a minute old, and answers from the last report if
  that report is less than ten seconds old. `cloop_hub_health_reports_total`
  counts the reports by what triggered them.
- **Who sees it.** Anyone with `config.write` across the hub, as for the
  hub-wide Settings around it. Under an enforced role policy, a viewer or an
  operator gets `403`, and their page never asks for the report. An
  administrator's header shows a red ⚠ count while any check fails. The member
  pushes each report's summary (the failing count, its generation, when it was
  made and when the next is due) over the dashboard's socket as the
  `hub_health` event. It sends the summary only to sockets whose identity may
  read the report, judged on the identity as it is now: the session's current
  claims, the token as it reads now. The member checks again at once when a
  session's claims are refreshed or the session ends, or when a token or the
  static token is revoked, and every thirty seconds for changes nobody
  announced, such as a runtime role binding. A socket that may no longer read
  the report is told so, without a count, if it was sent the summary or opened
  while its identity could read the report (its page then read the summary
  itself), and its page turns the indicator off. Deliveries go out one at a
  time with the latest report, so a withdrawal is never overtaken by a count
  decided before it. A page asks for the report only when its socket opens or
  reopens. While Settings → Hub health is on screen, the page re-reads the full
  report when a new one is pushed, so an administrator's open page costs the
  member nothing beyond the reports it makes anyway.
- **What leaves the hub.** Every title, message, remedy and detail goes through
  two redactions first. The first removes the exact credential values the hub's
  configuration and environment hold (provider keys, the OIDC client secret,
  webhook URLs and headers, the password in any configured URL, and every
  `*_TOKEN`, `*_SECRET`, `*_PASSWORD` and `*_KEY` variable). The second applies
  the [credential-shape registry](../reference/credential-patterns.md). The page
  renders the result as text, so a name containing markup is shown as that
  markup.

Each finding links to its group's row in the table above. To get the same
report from a script, use an API token with `config.write`:

```console
$ curl -s -H "Authorization: Bearer $TOKEN" https://hub.example.com/api/hub/health \
    | jq '.member, (.findings[] | select(.severity == "fail") | {check, message, remediation})'
$ curl -s -H "Authorization: Bearer $TOKEN" 'https://hub.example.com/api/hub/health?summary=1' | jq .failing
```

### Dispatch health: `cloop hub doctor --smoke`

The checks above only read configuration. They can't catch a common failure
after enrolling a device: every check passes, but the first real task still
fails, because the harness image has no shell, or has an `ENTRYPOINT` that
swallows the arguments, or the agent can't write to its workspace, or the
driver drops credential files it claims to support.

`--smoke` runs a trivial workload through the same steps a real task goes
through and reports each step separately.

```console
$ cloop hub doctor --smoke                          # every non-cordoned executor
$ cloop hub doctor --smoke --executor edge-01       # one device
$ cloop hub doctor --smoke --json | jq '.smoke[] | select(.first_failure != "")'
```

```
DISPATCH SMOKE TEST
  container (container, isolation container) — 426ms
    ✔ placement      the scheduler would place a task on container
    ✔ workspace      the workload read a file the hub wrote and could write its own
    ✔ lease          the sandbox opened the leased credential file and it held this run's material
    ✔ dispatch       the workload ran in the sandbox and exited 0
    ✔ logs           streamed 130 bytes, complete and correctly attributed
    – write_back     this backend shares its workspace with the hub, so there is nothing to write back
    ✔ revocation     the credential was destroyed and the lease no longer renews
    ✔ cleanup        every container, credential and directory this run created was removed
    the dispatch circuit works end to end
```

| Stage | What a failure means |
| --- | --- |
| `placement` | The scheduler would not choose this executor at all: host-execution policy, a cordon, or an agent below `executors.min_agent_build`. |
| `workspace` | The sandbox got no usable working directory. On a driver that shares the filesystem, it could not see a file the hub wrote. |
| `lease` | A throwaway credential is minted, granted and delivered. A failure names the delivery path, not the grant. |
| `dispatch` | The workload did not start, or exited non-zero. The last lines of its output are in `--json` under `details.output`. |
| `logs` | Output did not come back, was truncated, dropped chunks, or carried another run's id. The last is a confidentiality problem on a multi-tenant hub, not a logging bug. |
| `write_back` | A driver asked for a write-back produced no result, so a task's commits would be made in the sandbox and lost without an error. |
| `revocation` | The credential outlived its lease. This is checked by stat-ing the files and asking the broker to renew. |
| `cleanup` | Something this run created could not be removed. |

A stage reports `skip`, never `pass`, when it doesn't apply to the backend or
can't be checked hermetically: `write_back` on a driver whose workspace *is* the
hub's directory, or `lease` on a driver that can't take a credential back.
Currently `write_back` is skipped everywhere. A write-back is measured against
the commit the sandbox's tree was built from, which needs a tree the driver
built from git, and the smoke workload runs in a plain directory. A run of a
project with a git workspace, or of a feature, exercises it.

**It is safe to run against production.** The workload uses no network, clones
no repository and calls no model. The credential it mints is a kubeconfig
pointing at `127.0.0.1:1` with a TTL of seconds, and it is destroyed, and
checked to be destroyed, before the command exits. Its lease carries that
credential and nothing else. Every other grant aimed at the executor (a real
kubeconfig, a PAT, anything) is withheld before its payload is opened, with one
audit row each, so none reaches the smoke sandbox whatever `kube_guard` or
`git_proxy` say. Everything else (the container, workspace, lease directory,
and the secret and grant rows) is removed on every exit path, including
Ctrl-C. Anything that could not be removed is named in the report, and the
command exits 5.

**Exit codes.** You can use it as a Kubernetes readiness gate or a post-deploy
CI step without parsing JSON:

| Code | Meaning |
| --- | --- |
| 0 | every target smoked clean |
| 1 | a configuration check failed (the hub is misconfigured regardless of dispatch) |
| 3 | no executor to dispatch to, which is *not* the same as healthy |
| 4 | an executor failed a stage |
| 5 | the run could not clean up after itself and needs a person to look at it |

By default it tests every executor that isn't cordoned, so one command tells
you which of your devices is broken. Cordoned and draining devices are skipped,
and the report lists them, so that a clean result for seven of ten devices
isn't read as a clean result for all ten. Naming a device with `--executor`
tests it anyway, which is how you check that a cordoned device is fixed before
you return it to rotation.

It starts a container per executor, so don't run it on every kubelet poll.
Point the liveness probe at `/healthz`, and run this on a timer or after
deploys.

---

## The control-plane lease

Several hubs can serve one `state.db` as members of one cluster. Every
`cloop ui` joins the control plane in its working directory. Start more in the
same directory, or raise `replicaCount` in the Helm chart, and they serve the
same state behind one load balancer. They share the database, forward each
other the requests only one member can answer, relay live events between their
dashboards, and elect one leader for the work that must happen exactly once.
[Hub cluster](../architecture/hub-cluster.md) describes how.

The leader holds the lease. It runs retention, backups, auto-resume, the
session janitor and the periodic orphan sweep. The other members serve
everything else.

```console
$ cloop hub cluster status
Hub cluster
  /srv/cloop/.cloop/state.db

  hub_59f28a07ceea8b8fa2b4386edc1cef40 leader  serving
      host hub-1 pid 1234, listening :8080, reachable at http://127.0.0.1:8080
      version v0.9.0, started 2026-09-12T17:23:15Z
  hub_d74093a016f4198a7ec530075841bd4f  serving
      host hub-1 pid 1301, listening :8081, reachable at http://127.0.0.1:8081
      version v0.9.0, started 2026-09-12T17:25:02Z

  2 member(s) serving

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
| Clean shutdown (SIGTERM, `helm upgrade`, `systemctl restart`) | The member hands over its runs and agents, releases the lease if it led, and leaves. Another member, or the restarted process, leads within seconds. |
| A member killed outright (SIGKILL, OOM) on the same host | The others probe its recorded pid and take over at once: its runs are adopted, and if it led, a new leader is elected. |
| A member gone on another host or node, in another container, or after a reboot | The pid can't be trusted. The member counts as dead after 20s of silence and its runs are adopted. If it led, the lease lapses at its last heartbeat + 60s. |
| A leader paused past the TTL and its lease taken | It steps down and keeps serving as a member. |
| A second hub started in the same directory | It joins as a member. |
| A hub from before clustering holds the lease | A current build refuses to start alongside it; see below. |

None of this needs an operator, including after a crash. A stale lease is free
to take, so a dead hub can't block its own restart.

### When a hub refuses to start

In two situations a hub refuses to start instead of joining.

**A hub from before clustering is serving.** It holds the lease without being a
member, so it would neither forward requests to a new member nor see its
events:

```
Error: another cloop hub controls this state and cannot share it

  holder     hub_59f28a07… on hub-1 (pid 1234), serving :8080
  version    v0.8.2
  last beat  4s ago
```

Upgrade it or stop it. Restarting it is enough, because the old process
releases the lease as it exits. If it was killed instead of stopped, a new
build on the same host probes its pid and starts at once. On another host, its
lease has to lapse first, which takes up to a minute.

**`ui.cluster.exclusive` is set**, on this hub or on the one already serving.
The setting restores the pre-cluster rule of exactly one process, and the
error names the member that is serving. Stop that member, or remove the
setting to let them join.

In either case:

1. Run `cloop hub cluster status` and `cloop hub lease status` to see who is
   serving and who holds the lease. Is the holder this machine, and is its pid
   alive?
2. If you meant to run one hub, stop the other. Under Kubernetes, look for a
   Pod of an older release.
3. If the holder really is gone, wait for `lapses in` to reach zero.
   `cloop hub lease clear` releases a lapsed lease explicitly, and refuses while
   the lease is live. There is no `--force`, because a live lease means a hub is
   renewing it right now.

---

## Backup and restore

### Backup

`cloop db backup` uses `VACUUM INTO` under a read transaction, so it is safe
while the hub is running and tasks are executing.

```console
$ cloop db backup
cloop db backup
  source: /srv/cloop/.cloop/state.db
  output: /srv/cloop/.cloop/backups/state-20261011T112707Z.db

  WAL checkpoint:  TRUNCATE log_frames=0 checkpointed=0
  size:            892.0 KB
  duration:        32ms
  sha256:          0495b530781c1654129e99b9b3d9e5e569beb584fb9cdd57eac9c39514408063
  schema version:  65
  audit head:      id 9 (212d86cf4c7e…)
  sealing keys:    1, sealing 1 row(s)
  metadata:        /srv/cloop/.cloop/backups/state-20261011T112707Z.db.meta.json
  sidecar seal:    under CLOOP_SECRET_KEY a9a0a761a2b0ee6e

Backup complete.
```

`--output <path>` changes the destination. The `.meta.json` sidecar records the
SHA-256, size, source, schema version and duration. It also holds the
**manifest**, which a restore checks before it changes anything: the sealing
keys the backup's secrets, sessions and hub CA keys are sealed under, how many
rows each key seals, and where the backup's audit chain ends. The manifest is
read back from the copy, not from the live database.

The whole sidecar is **sealed** with an HMAC under a key derived from
`CLOOP_SECRET_KEY` with its own label, the same construction the audit
checkpoints use. The seal carries the key's fingerprint, which every checkpoint
and escrow of that key also carries. Nothing in a database can produce the
seal, and neither can an attacker who holds only the backup, so a restore
refuses a backup that was edited and had its SHA-256 recomputed. Without
`CLOOP_SECRET_KEY` the sidecar is written unsealed and the backup output says
so; restoring it then needs `--allow-unsealed`. Backups made by a hub's
`backup.auto_backup` are sealed the same way.

Keep the sidecar with the backup. Restoring without it needs `--skip-checksum`,
which checks nothing.

A backup contains sealed secrets. It isn't plaintext, but it is half of a
plaintext secret store. The other half is the root key (in `hub.env`, or in
the key file a newer hub reads through `CLOOP_SECRET_KEY_FILE` or a systemd
credential), or its escrow. On a hub whose keys are
[held by a KMS](#keys-in-a-kms), the other half is the KMS key, and a backup
only restores where that key answers. The report then says
`sealing keys: … held by the KMS …`, and you have to keep the KMS key, and
every version of it the backup's keys were wrapped under, for as long as you
keep the backup.

A nightly backup, kept for 30 days:

```bash
cloop db backup --output /var/backups/cloop/state-$(date -u +%Y%m%dT%H%M%SZ).db
find /var/backups/cloop -name 'state-*.db*' -mtime +30 -delete
```

### Escrowing the sealing key

Every key-encryption key is derived from `CLOOP_SECRET_KEY`, so rotating them
doesn't protect you against losing that key. If you lose the key file, every
sealed secret, session and hub CA key is lost with it. Escrow the key once the
hub has started, and again after every
[change of root](#changing-cloop_secret_key-itself); the change won't finish
until the new key is escrowed. (On a hub whose keys are
[held by a KMS](#keys-in-a-kms), no escrow opens them, and the commands list
those keys as `KMS-HELD`. The escrow still recovers the audit checkpoint key
and the backup sidecar seals, so keep making one.)

```console
$ cloop hub key escrow export --output /mnt/root-credentials/cloop-hub.escrow
Escrow passphrase:
Again:
Escrowed CLOOP_SECRET_KEY
  file:          /mnt/root-credentials/cloop-hub.escrow (opened again to check it)
  escrow:        esc_881bc88ef57b3a35
  key:           a9a0a761a2b0ee6e
  derivation:    argon2id t=3 m=64MiB p=4, then aes-256-gcm
  recorded in the hub: the escrow id and key fingerprint, nothing secret
```

The file holds the key sealed under your passphrase: argon2id with RFC 9106's
second recommended parameters, then AES-256-GCM, with every header field bound
into the cipher's associated data. The command reads the file back and opens it
before it reports success. The escrow is only as strong as the passphrase. A
passphrase under 15 characters is refused; five or six random words is a good
choice. Keep the file where you keep root credentials, off this host (a path
inside `.cloop/` is refused), and keep the passphrase somewhere else again. The
key is never written to disk on the way out. `--passphrase-file <file>` (or `-`
for stdin) replaces the prompt.

The command refuses a `CLOOP_SECRET_KEY` that doesn't open this hub's sealing
keys, because escrowing the wrong key is worse than escrowing none. During a
change of root it escrows the new key and counts the old one alongside it:
together they open every key, and the retire step waits for this escrow. The
hub records the escrow's id and the key's fingerprint and nothing else.
`cloop hub doctor` reports `secret_key.escrow`: a warning while no escrow is
recorded, and a **failure** when the escrow on record holds a different key
from the one in use. During a change of root, an escrow that holds the previous
key is only a warning.

### Restore

Stop the hub first, then check the backup before restoring it:

```console
$ cloop db restore /var/backups/cloop/state-20261011T112707Z.db --check
…
  SEALING KEY                   STATE    SEALED ROWS  OPENS
  kek_814ca52cd82fe6c050dc0ae2  primary  secrets=1    yes

PASS — this backup restores under this key.
$ cloop db restore /var/backups/cloop/state-20261011T112707Z.db --force --reason "disk failure on hub-1"
```

`--reason` is required and is recorded. Before anything changes, a read-only
preflight checks everything the restore depends on. If any check fails, the
restore is refused and nothing changes. Each error names the flag that
overrides it:

| Refusal | Means | Overridden by |
| --- | --- | --- |
| integrity, schema | `PRAGMA integrity_check` fails, or the backup's schema is newer than this binary | nothing |
| no sidecar | there is no `.meta.json` beside the backup | `--skip-checksum`, which checks nothing |
| checksum mismatch | the file is not the one its sidecar describes | `--skip-checksum` |
| seal does not verify | the backup and its SHA-256 were changed after it was taken, or the sidecar was | `--skip-checksum` |
| seal cannot be checked | the sidecar is unsealed (taken before sidecars were sealed, or without a key), sealed under another key, or there is no `CLOOP_SECRET_KEY` here | `--allow-unsealed`; the digest is still checked |
| sealing keys | neither the `CLOOP_SECRET_KEY` here nor `CLOOP_SECRET_KEY_PREVIOUS` can derive a key the backup's secrets, sessions or hub CA keys are sealed under | `--accept-secret-loss` |

```console
Refused — nothing was changed:
  • the CLOOP_SECRET_KEY here (key 8260957539fa2819) cannot open the backup's sealing keys
    kek_814ca52cd82fe6c050dc0ae2 (1 secrets): every secret, session and hub CA key sealed under
    them would be unreadable, and the hub would refuse to start on them. Restore the key they
    were sealed under (`cloop hub key escrow import`)
    --accept-secret-loss proceeds anyway
```

The key check is the same one the hub makes when it starts, made before the
swap instead of after. The fix for it is the escrow, not a flag.
`--accept-secret-loss` is separate from `--force`, which only allows
overwriting a live database. It is for when there is no escrow: it restores
anyway and **retires** the keys it can't open in the restored database (every
key the hub would refuse to start on), so the hub can start and mint a fresh
one. Every secret sealed under the retired keys then reports that its key was
retired. The flag is recorded on the restore's audit row and in its restore
record. The backup file keeps the keys, so you can restore it again under the
right key to get them back. The flag needs a `CLOOP_SECRET_KEY` (the new one
the hub will run on), because a variable missing from your shell is not a lost
key: with no key set, the restore is still refused.

A backup taken before the hub's key was [changed](#changing-cloop_secret_key-itself)
holds keys that only the old root derives, and its sidecar is sealed under the
old root. Restore it with the old key as `CLOOP_SECRET_KEY_PREVIOUS` alongside
the new one; its keys open, and its seal checks, under either. Run the restored
hub the same way, and finish with `cloop hub key rotate --retire-previous`
again: the old root's restored keys are live again, and the retire step moves
them onto the new one. The restore record is sealed under the new key, and
checkpoints sealed under the old one still account for what the restore gave
up.

`--force` first moves the existing database aside as `.pre-restore.<UTC>`,
together with its `-wal` and `-shm` files, which would otherwise be replayed
into the restored file. That way, restoring the wrong backup can be undone too.
A restore never takes a database away from a hub that is still serving it:
while a hub holds the control-plane lease, or a cluster member is live, the
restore is refused, because a hub writing to the moved file would lose
everything it wrote after the swap. The backup is hashed as it is copied, and a
file that changed between the preflight and the copy is not restored. Exit
codes: 0 restored and recorded; 1 refused or failed, nothing changed; 2 the
restore could not run; 3 restored, but the record of the restore is incomplete
(the output says what is missing).

#### What a restore records

To the audit checkpoints, a restore looks the same as a tail deleted while the
hub kept writing: the rows the newest checkpoints saw are gone, and new rows
take their ids. So a restore records itself in two places, each out of reach of
the other:

- an `audit.restored` row, appended to the restored chain, with the backup's
  SHA-256 and time, the head the chain was restored to, the newest checkpoint
  superseded, the events lost, who ran the restore and why;
- a **restore record**, sealed under the checkpoint key and written to
  `audit.checkpoints.file` (or `--checkpoints <file>`) and stderr. It says the
  same and pins that row's hash.

`cloop hub audit verify --checkpoints` accepts the restore record as the
explanation for checkpoints sealed before it that saw past the restored head.
It reports the restore and exits 0:

```console
RESTORED      control-plane /srv/cloop/.cloop/state.db — acknowledged
  3 checkpoint(s) agree with the chain; the newest, at 2026-10-11T11:28:04.819549679Z, saw id 13
  restored (acknowledged): 5 events lost between 2026-10-11T11:27:07.34123538Z and 2026-10-11T11:27:30.227423779Z, by cli:root, reason "disk failure on hub-1"
    restore record on line 3, sealed under key a9a0a761a2b0ee6e; backup sha256 0495b530781c… taken 2026-10-11T11:27:07.406627001Z, restored to id 9; 2 checkpoint(s) superseded
```

The lost window runs from the newest event the backup holds to the newest
checkpoint that saw what came after. Events written after that checkpoint
aren't counted, because nothing outside the database recorded them. A restore
of a backup whose sidecar was not checked (`--skip-checksum`,
`--allow-unsealed`) is acknowledged the same way and says so: "from a backup
nothing vouched for". `cloop hub doctor` reports the restore as a warning on
`audit.checkpoints.chain` for as long as it is among the 50 newest checkpoints
it reads.

Only a record sealed under the key the verifier holds explains anything, so
that write access to the database or the file is never enough to explain a
truncation away. A hand-written or unsigned restore record is refused. A record
sealed under another key explains nothing. A record dated ahead of the
verifier's clock is refused. A record whose own head, or the head it says the
chain was restored to, is no longer in the chain fails as `restore-mismatch`. A
record only accounts for checkpoints sealed before it, so a tail deleted after
the restore, while the hub keeps writing, is still a finding.

To restore a project's database, run the same command in the project's
directory. The project's configuration doesn't name the hub's checkpoint file,
so pass it: `--checkpoints /var/log/cloop/audit-checkpoints.jsonl`.

### Disaster recovery drill

Rehearse the whole recovery, including the case where the key file is gone, in
a scratch directory. Don't use the live hub:

```bash
# 1. The escrow still opens, its passphrase is still known, and it holds the
#    key this hub runs on. Run it where the hub's key is: CLOOP_SECRET_KEY_FILE
#    pointing at its key file (or, on an older hub, its hub.env loaded).
cloop hub key escrow verify /mnt/root-credentials/cloop-hub.escrow
#    → OPENS, IN USE, OPENS THE HUB, ON RECORD

# 2. A fresh directory with no key, as after losing the host.
mkdir -p /tmp/cloop-drill/.cloop && cd /tmp/cloop-drill
alias nokey='env -u CLOOP_SECRET_KEY -u CLOOP_SECRET_KEY_FILE -u CLOOP_SECRET_KEY_PREVIOUS \
  -u CLOOP_SECRET_KEY_PREVIOUS_FILE -u CREDENTIALS_DIRECTORY'
nokey cloop db restore /var/backups/cloop/state-<UTC>.db --check
#    → Refused: there is no CLOOP_SECRET_KEY here to open the backup's sealing keys …

# 3. Recover the key from escrow into this directory's key file.
nokey cloop hub key escrow import /mnt/root-credentials/cloop-hub.escrow
export CLOOP_SECRET_KEY_FILE=/tmp/cloop-drill/cloop-secret-key

# 4. The backup now restores under it, and its credentials deliver.
cloop db restore /var/backups/cloop/state-<UTC>.db --check            # → PASS
cloop db restore /var/backups/cloop/state-<UTC>.db --reason "DR drill" \
    --checkpoints /tmp/cloop-drill-checkpoints.jsonl
cloop secret lease --project <a project holding a grant>              # → its materials
cloop hub audit verify --hub . --project .                            # → OK

# 5. Clean up: the directory holds the hub's key and its secrets.
cd / && rm -rf /tmp/cloop-drill /tmp/cloop-drill-checkpoints.jsonl
```

For a real recovery, in order:

1. Stop the hub. Don't restore under a running process.
2. If the key is lost, run `cloop hub key escrow import <file>` and point the
   hub at the key file it writes (`CLOOP_SECRET_KEY_FILE`, or re-encrypt it for
   a unit that loads it with `LoadCredentialEncrypted=`).
3. `cloop db restore <backup> --check`
4. `cloop db restore <backup> --force --reason "…"`
5. `cloop db verify`
6. Start the hub and confirm `/readyz`.
7. `cloop hub audit verify --checkpoints <file>` reports the restore as
   acknowledged, with the window it lost, and exits 0.
8. `cloop hub doctor`: `secret_key.escrow` passes. If the backup predates the
   escrow, record the escrow again with
   `cloop hub key escrow verify <file> --record`.
9. `cloop executor ls`: enrolled agents reconnect on their own backoff.

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

  size before:    541.9 MB (138739 pages, 4096 bytes/page, 38740 freelist)
  wal before:     152.2 MB
  last maintenance: 504h12m40s ago (vacuum+analyze, freed 1.96 GB)

Dry run — no changes written.
  estimated reclaim: 151.3 MB (freelist_count × page_size)
  write-ahead log:   152.2 MB (a real run truncates it)
$ cloop db maintain                         # with the hub stopped
cloop db maintain — VACUUM + ANALYZE
  …
  size after:     390.6 MB (99999 pages)
  wal after:      0 B (truncated)
  operations:     [VACUUM ANALYZE]

Reclaimed 151.3 MB.
```

`cloop db maintain` runs `VACUUM` + `ANALYZE`, records the run in
`maintenance_log`, and finally truncates the write-ahead log, through which the
`VACUUM` passed every page of the database. `--auto` does nothing
unless the database has grown more than 20 % since the last vacuum, which suits
a cron entry:

```bash
0 4 * * *  cloop db maintain --auto
```

`VACUUM` rewrites the database and needs free space roughly equal to its size,
or twice that while it runs, because the rewritten pages pass through the log
before the final checkpoint frees them.

### The write-ahead log

Every write to the database goes to `state.db-wal` first, and a checkpoint
copies it into `state.db`. Normally the log is a few megabytes. After each
checkpoint SQLite reuses the file from the start but never shrinks it, so a
burst of writes could leave the log at that size for as long as anything had
the database open. Such bursts are a `VACUUM`, which writes the whole database
through the log, and bulk deletes by row retention or `cloop hub audit prune`.
On 2026-10-06 cloop's own hub had a 340 MB log beside a 409 MB database, on a
disk that was 98% full. Three things keep the log bounded:

- **Every read-write connection trims it.** cloop opens its databases with
  `journal_size_limit` set to 64 MiB, so whichever connection starts the log
  over after a checkpoint cuts the file back to 64 MiB, or to the size of its
  own write if that is larger. On a busy hub that happens within seconds of the
  burst ending. Only connections from this version on do it: older builds
  sharing the database (a long-lived `cloop run`, a second dashboard started
  from an older binary) write without the limit.
- **The leader truncates it.** The leading hub runs
  `PRAGMA wal_checkpoint(TRUNCATE)` at the end of every retention pass, on every
  project's database as well as its own, and every minute while its own
  database's log is over 64 MiB. The checkpoint waits at most 250 ms for other
  connections. A TRUNCATE checkpoint holds the write lock while it waits, so the
  usual 5 s busy timeout would hold up every writer for that long and fail
  writers whose own 5 s ran out. It first copies the log back with a PASSIVE
  checkpoint, which takes no lock a writer waits on, so the TRUNCATE has little
  left to copy while it holds the lock. If a connection is still reading from
  the log, the checkpoint reports busy, nothing changes, and it tries again the
  next minute. The hub logs the first busy attempt, then one an hour:

  ```
  retention [/srv/cloop] write-ahead log is 324.2 MB, over the 64.0 MB limit, and another connection was still using it after 250ms (1 attempt(s) so far); retrying every 60 s
  retention [/srv/cloop] truncated the write-ahead log, 324.2 MB → 0 B, after 3 busy attempt(s)
  ```

- **`cloop hub retention --apply` truncates it** with the same short wait,
  whether or not a hub is running. **`cloop db maintain`**, which needs the hub
  stopped, ends every run that goes ahead the same way.

To see the log's size, use `ls -l .cloop/state.db-wal`, the
`cloop_statedb_wal_bytes` gauge ([metrics](metrics.md#control-plane-database)),
or `cloop hub doctor`'s `statedb.wal`, which warns once the log is larger than
both 64 MiB and a quarter of the database. `cloop db maintain` prints
`wal before:` and `wal after:`.

**A log that stays large** is being held. Either a connection keeps a read
transaction open the whole time (the leader's attempts every minute then all
report busy, and its log says so every hour), or every connection writing the
database predates the limit. `fuser -v .cloop/state.db-wal` lists the processes
that have the log open, and `go version -m` on `/proc/<pid>/exe` shows each
one's version. Until the older processes are replaced, the leader's checks keep
the file small. If no hub is running, `cloop hub retention --apply` truncates
it.

### A task row that will not load

Three task columns decide what runs: `depends_on`, `on_success` and
`on_failure`. If one of them holds something that isn't a JSON list (after a
truncated write, a restored backup or a hand edit), every load of the project
fails with an error that names the row. Reading the value as "no dependencies"
would release the task early:

```
task 7: column depends_on is not decodable JSON ("[1,2"): statedb: corrupt task column: unexpected end of JSON input
```

Saves are refused too, because a save replaces every stored task and would
delete or overwrite the one the error names. A run in progress therefore stops
at its next write instead of carrying on with work it can no longer record (see
"A run stopped: run progress could not be saved" below). Back up, then write
the list you want:

```console
$ cloop db backup
$ sqlite3 .cloop/state.db "UPDATE plan_tasks SET depends_on = '[1,2]' WHERE id = 7"
```

A damaged `tags`, `annotations` or `links` value doesn't stop the load. The
field reads as empty, and the hub logs `statedb: task N: column C is not
decodable JSON, field dropped` once per damaged value.

Migration 0054 adds columns that `cloop migrate` or a development build may
already have created. It adopts an existing column only if it matches the
declared column exactly. Otherwise startup fails with `plan_tasks.<column>
already exists as <what is there>, but this migration declares it <what 0054
wants>`. Check what the column holds, then drop it
(`ALTER TABLE plan_tasks DROP COLUMN <column>`) or rebuild it to match, and
start cloop again.

---

## Disk space low

A run doesn't start work on a disk too full to record the result. Before every
task attempt and every evolve round, it measures the volume holding the
project's `.cloop` and the working tree's volume. Below
`orchestrator.min_free_disk_mb` (default 1024 MB), nothing starts and the run
pauses with reason `disk_low`.

**What you see.** The project shows *Paused: volume / has 812.3 MB free, below
the 1.00 GB floor* with a **Stop** button, because the run is still up. It
measures again every minute and carries on by itself once every volume is back
above the floor plus a tenth (1.1 GB with the default). The event history has a
`session_paused` row with `pause_code: disk_low`, the volume, the free bytes,
the floor and what was about to start. When the run carries on, a
`session_started` row "Run resumed: disk space recovered" follows. In parallel
mode, the round in progress finishes and records its outcomes first, and no new
task starts. While the hub's own state volume is below the floor, admins also
see a banner across the dashboard, `cloop hub doctor` fails
`storage.free_space`, and `cloop_hub_disk_free_bytes{volume}` shows the trend.
Alert on that metric at twice the floor, before runs start pausing.

**What to do.** Free space on the volume the message names; the run notices
within a minute. The usual places to look, largest first on a busy hub:

```console
$ df -h /                                   # what the run measured
$ ls -l .cloop/state.db-wal                 # the write-ahead log; see "The write-ahead log"
$ cloop hub retention                       # dry run: what the janitor would reclaim
$ cloop hub retention --apply               # ...and reclaim it, including VACUUM and the log
$ cloop compact --dry-run                   # per project: old artifacts, snapshots, checkpoints
$ go clean -cache                           # on a build host: often gigabytes
$ du -sh /tmp/* 2>/dev/null | sort -h | tail # test runs leave scratch here
```

Before deleting a file in `/tmp`, check what it belongs to (`lsof +D`), because
it may hold another run's work. To end the wait instead, press Stop. The pause
is recorded as stopped while waiting for disk space, and the next Run checks
again.

**The reserve.** Each project keeps `.cloop/reserve`, 16 MiB of preallocated
blocks, put in place whenever the check passes. If the disk still fills up
between the check and the write of a task's verdict or outcome (usually because
of the task's own build), the run deletes the reserve, writes again into the
space that frees, and then pauses `disk_low` before starting anything else. Its
pause detail then begins "task #N's verdict only reached the disk by releasing
the 16.0 MB free-space reserve". The reserve comes back by itself at the next
check that has room. Only if the second write fails too does the run stop, with
`state_not_persisted`. Free space, then press Run; the next run recovers the
tasks the stopped one left in progress. The reserve holds no data: snapshots,
`cloop compact`, the janitor and the disk-usage reports leave it out, and
deleting it by hand does no harm.

**Tuning.** Set the floor in **Settings → Disk & Retention** (admins), with
`cloop config set orchestrator.min_free_disk_mb <MB>`, or in a project's
`config.yaml`. `0` turns off the check and the reserve. The hub doctor then
warns, because a full disk can corrupt outcomes again. A run in the hub's own
directory gets the Settings value even when it is stored in the per-instance
overlay; every other project's run reads its own `config.yaml`. See
[Free-space floor](../reference/configuration.md#free-space-floor).

A run killed while it waited (an OOM kill, a host reboot) leaves the waiting
pause behind. When the hub notices, it settles it as *previous run ended
unexpectedly*, the same as a stale "running".

## A run stopped at its disk limit

A container executor keeps a workload's workspace within its disk limit
(`.cloop/sandbox.yaml` `resources.disk`, or an operator's disk ceiling) by
measuring it while the workload runs. This is separate from the free-space
floor above: the floor protects the volume, and the limit caps one project's
share of it.

**What you see.** The project shows *Paused: the workspace grew to 21.3 GB, over
its disk limit of 20 GB (from .cloop/sandbox.yaml resources.disk); free space in
the workspace, or raise resources.disk …, then press Run*, with a **Start**
button: the run was stopped (SIGKILL) and is not retried. The task it was
running is back to pending, with a note from cloop giving both sizes. The event
history has a `disk_limit` row with `disk_used_mb`, `disk_limit_mb` and the
workspace path in its details. The task's `task.finish` audit row carries
`stop: disk_limit`, and the workload's own output ends with
`[cloop] disk limit: … stopping the workload`.
`cloop_executor_task_failures_total{reason="disk_limit"}` counts these stops.

**What to do.** Decide which is wrong, the tree or the limit:

```console
$ du -sh --exclude=.cloop /srv/projects/api   # what the limit counts (allocated size)
$ du -h --max-depth=2 --exclude=.cloop /srv/projects/api | sort -h | tail
```

Then either free space in the workspace (build output, caches, a dataset the
task shouldn't have downloaded there), or raise the limit: `resources.disk` in
the project's `.cloop/sandbox.yaml`, or, when the message says *an operator's
disk ceiling*, the executor's **Limits** in the Executors panel, the project's
ceiling (`cloop hub limits set <project> --disk …`), or
`executors.limits.max_disk`. Then press Run. A workspace that is still over the
limit is refused at the start with both sizes in the error, so pressing Run
without doing either won't start a run that would only be stopped again.

**A `disk limit: could not measure the workspace … unknown` line** in a
workload's output means a measurement missed its one-minute deadline or reached
a directory the measuring user can't read. It isn't counted as under the limit,
and the next attempt waits ten times as long as the failed one took. If a tree
routinely takes that long to walk, split it or exclude parts of it (move caches
out of the workspace). Where the walk doesn't run as root (a device's agent, a
hub on rootless podman), an unreadable directory is one the workload made
unreadable, and its contents are not counted.

**An executor that can't enforce it** (the host-process driver, a device running
payloads on its host, a device whose agent predates protocol v20) shows
`disk: not supported` on its card. A project that sets `resources.disk` is
refused there at placement, with constraint `disk_limit` for an agent older
than v20 and `resource_limits` for an executor that enforces no limits at all.
A disk ceiling that covers such an executor is reported in the project's
journal on every dispatch as not limiting the run. Upgrade the agent, or run
the device's payloads in a container.

## Audit chain verification

`audit_events` is hash-chained: each row's `row_hash` covers its content and the
previous row's hash, so editing or deleting a row breaks the chain from that
point. There are two chains, in the hub's control-plane `state.db` and in each
project's `.cloop/state.db`. Verify both:

```console
$ cloop hub audit verify --hub /srv/cloop --project /srv/projects/api
OK            control-plane /srv/cloop/.cloop/state.db — 18213 events verified
GAPS          project       /srv/projects/api/.cloop/state.db — 912 events verified
  1 recorded gap covering 37 lost event(s): audit.gap rows #640
```

`cloop audit-log verify` checks the one chain the working directory resolves
to. Both commands exit **0** when the chains are intact, **2** when one is
broken (naming the row id and the reason), and **3** when they are intact but
hold recorded gaps. Run `cloop hub audit verify --checkpoints <file>` on a
schedule and alert on anything but 0: a break means corruption or tampering,
and a gap means lost evidence.

### Gaps: events that could not be appended

An audit append can fail when the database is locked past its retries,
read-only, or on a full disk. A failed append leaves no hole in the hash chain
(the next append links to the last one that succeeded), so the append path
itself counts every failure, by chain, action and cause, and reports it on
stderr: the first at once, then a summary at most once a minute:

```
[audit] could not append to the audit trail at /srv/cloop/.cloop/state.db: statedb audit: begin: database or disk is full (13) — counting every failure from here on; they are recorded as an audit.gap row once the database takes writes again (3 event(s) so far: executor.cordon ×2, session.revoked ×1)
```

When the database takes writes again (at the next append that succeeds, at a
flush every 30 seconds, or when the hub shuts down), cloop writes one
`audit.gap` row into the same chain. It says how many events were lost, of
which actions, between which times, and why. The gap row is hash-chained like
any other, so the record of the loss is as tamper-evident as the events would
have been. To read the gap rows:

```console
$ cloop hub audit list --type audit.gap
```

Until a loss is recorded, only the process that suffered it knows about it. You
can see it in two places: that hub's Audit tab (a banner above the trail) and
`cloop hub doctor` (`audit.unrecorded`), which reads the status file the hub
keeps under `.cloop/audit-failures/`. A hub that dies with losses it hasn't
recorded leaves that file behind. The next hub started in the directory adopts
it and records the loss, naming the process it came from (`adopted_from`).
`cloop_audit_append_failures_total` and `cloop_audit_gap_events_total` count
the failures and the recorded losses ([metrics](metrics.md#audit-trail)).

Once the cause is fixed and the gaps are accounted for, `--allow-gaps` makes
verification exit 0 again. It still reports the gaps.

### Checkpoints: catching a shortened trail

The chain detects changes and insertions anywhere in the history, and deletions
anywhere except at the newest end. Truncating the newest rows leaves a shorter
chain that still verifies, and nothing inside the database can tell it apart
from a quiet period. **Head checkpoints** can. Every
`audit.checkpoints.interval` (5 minutes), the cluster leader (a lone hub is its
own leader) writes one record per chain: the newest row's id and hash, the row
count, the latest prune anchor, the time and the member. It writes one more at
a clean shutdown.

```yaml
audit:
  checkpoints:
    interval: 5m
    file: /var/log/cloop/audit-checkpoints.jsonl   # must lie outside .cloop/
    stderr: true                                   # the default
```

Each record is sealed (HMAC-SHA256) under a key derived from `CLOOP_SECRET_KEY`
with its own label, so nothing in `state.db` can forge one, and carries that
key's fingerprint. Records are appended to the file with an fsync, and printed
as one JSON line on stderr for a container platform's log pipeline to ship off
the machine. **Put the file on storage the database doesn't share.** A record
that the attacker who rewrote the database can also delete proves nothing.
Checkpoints are on by default, to stderr only. `cloop hub doctor` warns until a
file is set; you don't need one if a log pipeline already ships stderr off the
machine. A hub without `CLOOP_SECRET_KEY` writes unsigned records. They still
pin each head against anyone who can't write where they are kept, and the
doctor reports that they are unsigned.

Check the chains against them:

```console
$ cloop hub audit verify --hub /srv/cloop --project /srv/projects/api \
    --checkpoints /var/log/cloop/audit-checkpoints.jsonl
…
Checkpoints   /var/log/cloop/audit-checkpoints.jsonl — 4211 record(s)
  checking seals under key 9cfc998abbd68ba4 (from CLOOP_SECRET_KEY)
OK            control-plane /srv/cloop/.cloop/state.db
  3925 checkpoint(s) agree with the chain; the newest, at 2026-10-10T18:05:00.133126574Z, saw id 18213
TRUNCATED     project       /srv/projects/api/.cloop/state.db
  finding:  tail truncated after id 790 although a checkpoint at 2026-10-10T18:05:00.4Z saw id 812
  or:       the database was restored from a backup taken before then, and nothing has been written since
  1 of 286 checkpoint(s) disagree; the first is on line 4207
    line 4207   truncated        the chain ends at id 790, before the id 812 the checkpoint at 2026-10-10T18:05:00.4Z saw
```

`--checkpoints` also reads a log export of the stderr copies
(`journalctl -u cloop-ui -o cat`, `-o json`, or a container runtime's JSON log
file), so you can check the copy that left the machine as it arrived. Each
finding exits 2:

| Finding | Means |
| --- | --- |
| `truncated` | The chain ends before an id a checkpoint saw, and nothing was written since. Its tail was deleted, or a backup older than that checkpoint was restored and the hub has not run since. |
| `restored` | The chain no longer agrees with a checkpoint and has been written to since: a database restored from a backup older than that checkpoint (the report names the last checkpoint it still agrees with), or a tail deleted while the hub kept writing. |
| `rewritten` | The chain holds a different row under an id a checkpoint saw: history was edited and every later hash recomputed. The chain alone can't catch this kind of rewrite. |
| `deleted` | A row a checkpoint saw is missing from inside the chain. |
| `anchor-missing`, `anchor-rewritten` | A prune anchor a checkpoint saw is gone or altered. |
| `archive-mismatch` | A checkpointed row was pruned, and the archive its anchor sealed no longer matches the anchor's digest, or is not the intact chain the anchor's boundary ends in. Every archived row is re-hashed and linked, so a file that only holds the right hash on the right id doesn't pass. |
| `prune-unproven` | A checkpointed row is covered by a prune anchor whose archive cannot be read here, and no trusted checkpoint records the hub verifying that archive. Whoever can delete rows can also write an anchor over the hole, so until the archive is checked this is indistinguishable from a deletion. Run the command where the archive is. |
| `refused` | A record's seal does not verify under the key it claims: the file was edited or the record forged. Also an unsigned restore record when the verifier holds a key. It is not used as evidence. |
| `restore-mismatch` | A sealed restore record whose own head, or the head it says the chain was restored to, the chain no longer holds: the chain was cut back or rewritten after the restore it records. |

A checkpoint that disagrees with the chain because the database was restored is
not a finding when a restore record sealed under the hub's key accounts for it.
`cloop db restore` writes one, and verify reports `restored (acknowledged)` with
the events lost and exits 0; see [What a restore records](#what-a-restore-records).

A prune is not a truncation. A checkpoint below a prune anchor is checked
against the archive the anchor sealed: first the archive's digest, as
`verify-seals` would check it, then every row in it, re-hashed into the chain
the anchor's boundary ends in. The archive must hold the row with the hash the
checkpoint saw. An archive moved to cold storage is reported as unverified, not
failed, when a checkpoint sealed under the hub's key records that the hub
verified that anchor's archive itself. The hub reads each new anchor's archive
once, in the first window it sees the anchor, and prints a prominent warning on
stderr when one doesn't verify. Otherwise nothing outside the database vouches
for the prune, and it fails as `prune-unproven` until the command runs where
the archive is. An archive the hub verified and somebody deleted afterwards
still reads as unverified, not failed. The archives hold the copy of what a
prune removed, so keep `audit.export_dir` where whoever can rewrite the
database can't delete from. Records sealed under another key (because
`CLOOP_SECRET_KEY` was rotated since) are reported and still checked for what
they say. Without `CLOOP_SECRET_KEY` the seals aren't checked at all, and the
output says so.

Checkpoints can't stop someone deleting records from the file. Storage off the
machine covers that, and the doctor warns when the newest control-plane
checkpoint is more than three intervals old.

Checkpoints pin a chain's length. To keep its content off the machine, use the
forwarder described below; `cloop audit-log export` is for backfill.

### Forwarding the trail off the box

Whoever can write `state.db` can delete rows. A checkpoint shows that rows were
deleted, but only a copy kept somewhere else shows what they were. With
`audit.forward`, the cluster leader sends every row of every chain (the control
plane's and each registered project's) to one or more sinks as it is written:

```yaml
audit:
  forward:
    hostname: hub-prod-1         # names this hub in what it sends; set it in a cluster
    max_lag: 15m                 # `cloop hub doctor` warns past this (default 15m)
    sinks:
      - name: siem               # syslog: RFC 5424 messages, RFC 5425 framing
        type: syslog
        address: siem.corp.example:6514
        format: json             # or cef
        ca_file: /etc/cloop/siem-ca.pem
        client_cert: /etc/cloop/hub-client.pem
        client_key_secret: siem-client-key
      - name: splunk             # https: an NDJSON POST, or Splunk HEC events
        type: https
        variant: splunk_hec
        url: https://splunk.corp.example:8088/services/collector/event
        token_secret: splunk-hec
        splunk_index: cloop_audit
      - name: archive            # file: appended and fsynced
        type: file
        path: /mnt/audit/cloop/audit.jsonl
```

Every key is in the [configuration reference](../reference/configuration.md#audit-forwarding-auditforward).
Every member of a hub cluster must run the same `audit.forward`, so keep it in
`config.yaml` or in the same overlay on every member. Only the leader forwards,
using its own configuration. Members that disagree record the configuration as
changed at every change of leader, and each retires the other's cursors, which
releases their hold on retention.

**Credentials go in the secret store, never in the configuration.** A HEC token,
an API key or a client certificate's private key is a shared `env` secret in
the hub's secret store, and the sink names it. No field can hold the value
itself, and a URL containing `user:password@` is refused.

```console
$ cloop secret mint splunk-hec      --kind env --file hec-token.txt
$ cloop secret mint siem-client-key --kind env --file hub-client.key
```

A secret holding one value is presented as it is. For a secret holding several
(`{"API_KEY":"…","USER":"…"}`), name the one you want as `name#KEY`. A personal
secret is refused, because the hub presents only the organisation's
credentials as itself. The hub reads the secret when it starts a sink, after
any failed send, and at least every hour, so a rotated value is used within the
hour. To switch at once, point the sink's `token_secret` at a new secret.

**A file sink's directory must exist.** The sink never creates it, so a missing
directory fails the send. An unmounted mount point is still an existing, empty
directory, so put the file in a subdirectory that only exists on the mounted
volume (`/mnt/audit/cloop/`, not `/mnt/audit/`). A volume that isn't mounted
then makes the send fail with an error, and the rows don't land on the root
disk underneath.

**What is refused at load.** Plaintext (`transport: tcp`, or an `http://` URL),
unless the address is loopback *and* the sink sets
`allow_plaintext_loopback: true`; a local rsyslog or forwarder is the only case
where plaintext is acceptable. A file sink inside any `.cloop/` directory. A URL
with a query parameter that looks like a credential (`?api_key=`, `?token=`);
those go in the secret store too. A sink that fails these checks is switched
off, not repaired, and `cloop hub doctor` fails `audit.forward.sink`.

**What is refused on the wire.** The forwarder checks the address each socket
is about to connect to after DNS resolution, so a hostname can't get around the
checks. A cloud metadata service (from the
[same table](../guides/firewall.md#cloud-metadata-services) the firewall uses)
is refused for every sink, and a plaintext sink can only reach a literal
loopback address. The https sink follows no redirects (a 3xx is a failed send,
so the trail and its token are never carried elsewhere) and ignores
`HTTPS_PROXY`.

**Delivery.** Each sink has a cursor per chain in the control plane: the newest
row it acknowledged, by id and `row_hash`. A batch (`batch_size`, default 500
rows; `max_batch_bytes`, default 1 MiB) is read from the database after the
cursor and sent, and the cursor only moves once the sink acknowledges it:

| Sink | Acknowledged when |
| --- | --- |
| `https` | the collector answers 2xx (and, for HEC, with a body whose `code` is 0) |
| `file` | the batch is written and fsynced; a batch cut short is truncated back off the file, so a retry never lands after a half line |
| `syslog` | the receiver's TCP stack has acknowledged every byte, on a connection it has not closed. RFC 5425 has no acknowledgement of its own, so a receiver that crashes holding acknowledged bytes loses them; use `https` where the collector itself must confirm |

Delivery is **at-least-once**. If a leader dies after a sink acknowledged a
batch but before the cursor moved, its successor sends the batch again. A
receiver recognises the repeat by its `row_hash`, the idempotency key. Only the
leader forwards, so a cluster sends each row once per sink, not once per member.

A sink that is down never holds up an audit append. It has its own goroutine
and database handles, backs off from a second up to five minutes, and keeps its
backlog in the database: the forwarder holds at most one batch in memory
however far behind it falls. A new sink starts with every row still in the
database (`start: oldest`); `start: latest` starts at each chain's head. Rows
already pruned into archives, or written before the hub could forward, are
backfilled with `cloop audit-log export` (below).

**What a sink receives.** With `format: json`, each row is the record that
`cloop audit-log export --format jsonl` writes, plus the chain it came from and
the hub that sent it:

```json
{"id":4182,"timestamp":"2026-10-13T09:14:02.118409Z","actor":"alice@corp.example","event_type":"secret.grant","entity_type":"secret","entity_id":"s_7f3c","payload":{"decision":"allowed","secret_name":"gh-deploy"},"prev_hash":"9c1e…","row_hash":"4b07…","source":"project","dir":"/srv/projects/api","hub":"hub-prod-1"}
```

Over syslog the record is the MSG of an RFC 5424 message, `<PRI>1 TIMESTAMP HOSTNAME
cloop - MSGID - MSG`, with the event type as MSGID, facility `local0` unless
`facility` says otherwise. The severity is warning for a denial, notice for a
credential or executor event, and informational for everything else. A row
larger than `max_message_bytes` (default 8192) is sent without its payload and
says so (`payload_truncated`, `payload_bytes`, `payload_sha256`, an excerpt). `format:
cef` is the export's CEF line, adding `dvchost` (the hub), `cs5` (the chain's
role) and `cs6` (its directory) alongside `cs2` (`row_hash`) and `cs3`
(`prev_hash`). CEF truncates payloads, so you can verify a chain from CEF by its
links but not by its hashes.

**Verifying what a sink holds.** Every record carries `prev_hash` and
`row_hash`, so the copy is the chain itself, and you can check it without the
hub:

```console
$ cloop hub audit forward verify /mnt/audit/cloop/audit.jsonl
OK      control-plane /srv/cloop  ids 1…18213, 18213 row(s), 500 repeat(s)
OK      project       /srv/projects/api  ids 1…912, 912 row(s), 0 repeat(s)
```

It reads a JSON sink's file, a collector's export of the records (HEC events
are unwrapped), or syslog lines with the record after the header. For each
chain it reports missing ids, ids received with two different hashes (a
**fork**: the chain changed under the forwarder, through a tail truncated and
written past, a restored backup or a rewrite), records that don't hash to their
`row_hash`, and broken links. A receiver can run the same check itself.
`row_hash` is SHA-256 over `v1`, `prev_hash`, `id`, `timestamp`, `actor`,
`event_type`, `entity_type`, `entity_id` and the payload, separated by tabs,
with the payload as the chain holds it: the record's `payload` verbatim when it
is JSON, or the string it holds when it is a JSON string.

**When the chain moves under a sink.** A cursor whose row is no longer in the
chain (because a prune was forced past it, a tail was truncated after it was
sent, or the chain was rewritten) is a discontinuity. The forwarder resumes
from the newest acknowledged point that the chain still holds, so the sink
receives the chain as it now stands alongside what it already has. It records
an [`audit.forward.discontinuity`](../reference/audit-events.md#auditforward)
row naming the sink, the chain, the reason and any rows lost, and forwards that
row like any other. A change to the sinks themselves is recorded as
[`audit.forward.configured`](../reference/audit-events.md#auditforward) by the
first leader to run with the new configuration, however the file was edited.

**Watching it.**

```console
$ cloop hub audit forward status
✓ siem  syslog json → tls://siem.corp.example:6514
  backlog 0 row(s), lag 0s, delivered 18213 row(s), last acknowledged 2s ago
! splunk  https json → https://splunk.corp.example:8088/services/collector/event
  lags 2h14m3s behind, beyond audit.forward.max_lag (15m0s): 3210 row(s) waiting; last error: POST … answered 503 Service Unavailable
```

It exits 1 when a sink is refused, has never delivered (including a sink no hub
has started yet), or lags beyond `max_lag`. `cloop hub doctor` reports the same
as `audit.forward.sink`, `audit.forward.lag` and `audit.forward`, and the hub's
stderr has `[audit-forward]` lines when a sink starts and stops failing. The
[metrics](metrics.md#forwarding-the-trail-off-the-box) are
`cloop_audit_forward_rows_total`, `cloop_audit_forward_lag_seconds` and
`cloop_audit_forward_backlog_rows`.

**Retention waits for the sinks.** `cloop hub audit prune` and
`cloop db maintain` stop at the newest row every live sink has acknowledged,
and say which sink held back the rest. `--force` (`--force-audit-prune`) prunes
past it; those rows then reach the sink only through the archive, and the
forwarder records the loss. A sink removed from the configuration stops holding
back retention once the leader has run without it.

#### Splunk

Create an HTTP Event Collector token whose allowed indexes include the one the
sink names, store it as a secret, and point an `https` sink at the collector's
event endpoint with `variant: splunk_hec` (the `splunk` sink above). Each row
arrives as one event with `sourcetype=cloop:audit` and its record under
`event`. A resent row is a second event with the same `row_hash`, so
deduplicate searches on it:

```spl
index=cloop_audit sourcetype="cloop:audit" | dedup row_hash | table _time hub source dir event_type actor entity_id
```

Splunk truncates an event at `TRUNCATE` characters (10000 by default) for its
source type. The largest rows cloop writes are a few kilobytes, but raise the
limit for `cloop:audit` if a payload is bigger. A JSON reply whose `code` is not
0 is a refusal, and the batch is sent again. The exception is a reply refusing
the data itself (invalid format, a blank event): that chain then backs off on
its own while the others carry on. cloop sends a request channel, so a token
with indexer acknowledgement turned on accepts the batch. `code` 0 then means
received but not yet indexed, and cloop doesn't poll for the acknowledgement.

#### Elastic

Logstash's `http` input takes the NDJSON body as one event per line, and
Elasticsearch deduplicates a resend automatically when the document id is the
`row_hash`:

```conf
input {
  http {
    port => 8443
    ssl_enabled => true
    ssl_certificate => "/etc/logstash/tls.crt"
    ssl_key => "/etc/logstash/tls.key"
    user => "cloop"
    password => "${CLOOP_INGEST_PASSWORD}"
    codec => json_lines
  }
}
output {
  elasticsearch {
    hosts => ["https://es.corp.example:9200"]
    index => "cloop-audit"
    document_id => "%{row_hash}"
  }
}
```

```yaml
      - name: elastic
        type: https
        url: https://logstash.corp.example:8443/
        auth_scheme: basic
        token_secret: logstash-ingest    # an env secret holding "cloop:<password>"
```

(The option names are Logstash 8's; earlier versions spell `ssl_enabled` as
`ssl`.) For Elastic Agent's syslog/TCP inputs, use the `syslog` sink with
octet-counted framing (`framing: rfc6587`).

#### Microsoft Sentinel

Sentinel's *Common Event Format (CEF) via AMA* connector reads CEF from a Linux
log forwarder: rsyslog receives the messages and the Azure Monitor Agent ships
them into `CommonSecurityLog`. Send CEF over TLS to the forwarder's rsyslog:

```yaml
      - name: sentinel
        type: syslog
        format: cef
        address: cef-forwarder.corp.example:6514
        ca_file: /etc/cloop/forwarder-ca.pem
```

```conf
# /etc/rsyslog.d/10-cloop-tls.conf on the forwarder
global(DefaultNetstreamDriver="gtls"
       DefaultNetstreamDriverCAFile="/etc/rsyslog.d/tls/ca.pem"
       DefaultNetstreamDriverCertFile="/etc/rsyslog.d/tls/cert.pem"
       DefaultNetstreamDriverKeyFile="/etc/rsyslog.d/tls/key.pem")
module(load="imtcp" StreamDriver.Name="gtls" StreamDriver.Mode="1" StreamDriver.AuthMode="anon")
input(type="imtcp" port="6514")
```

Collect facility `local0` (or the sink's `facility`) in the connector's data
collection rule. CEF's custom strings land in `DeviceCustomString1…6`, so
`row_hash` is `DeviceCustomString2`:

```kusto
CommonSecurityLog
| where DeviceVendor == "cloop"
| summarize arg_max(TimeGenerated, *) by RowHash = DeviceCustomString2
| project TimeGenerated, Hub = DeviceName, Chain = DeviceCustomString6, DeviceEventClassID, SourceUserName
```

#### Backfill with export

To fill in rows already pruned into archives, rows written before a sink was
configured with `start: latest`, or a time range a collector lost, export them
on demand:

```console
$ cloop audit-log list --entity secret --since 7d
$ cloop audit-log export --format jsonl --since 2026-09-01 --until 2026-10-01 --verify --output backfill.jsonl
$ cloop audit-log export --format cef --since 24h --verify | logger -t cloop -p local0.notice
```

| Format | Use |
| --- | --- |
| `jsonl` | lossless, with structured payloads; use it for archives |
| `csv` | flat table for spreadsheets |
| `cef` | ArcSight Common Event Format, syslog-ready |

### Reconstructing one task

Auditors usually ask about a single piece of work: *which executor ran task 63,
under which secret leases, and how did it end?*

```console
$ cloop audit-log --task 63
Task #63 — Provision the staging cluster
2 execution(s) recorded

── run 1/2  run_0123456789abcdef0123456789abcdef
   executor    edge-pi4  kind=remote  isolation=remote
   actor       alice@example.com
   image       ghcr.io/acme/harness@sha256:3f1a…
   sandbox     spec sha256:9c4e0b1a7d22
   leases      lease-7f3c
               2026-09-15 09:14:02  secret.lease  gh-deploy-key
   outcome     failed  after 1m30s
   reason      terraform apply exited 1: quota exceeded in eu-west-1
```

This reads `audit_events` and no other table: not the plan, and not the task
record. An auditor reviewing an incident often has an exported trail but no live
database, and a reconstruction that needed the hub's working state would be
useless then. A test in `pkg/statedb` drops `plan_tasks` before reconstructing,
so this can't break unnoticed.

It joins rows on the **run id**, which every dispatch, terminal and lease row
carries. A task id isn't enough: task 63 above ran twice, and each run held a
different credential. Joining credentials on the task id would wrongly report
that the task held both credentials the whole time.

| Event | Written when |
| --- | --- |
| `task.dispatch` | a task starts executing; records the executor, isolation, pinned image digest, sandbox spec hash, lease ids and actor |
| `task.finish` | it stops executing, by any path (signal, kill, timeout, provider abort, or a hub crash reconciled later); records the outcome, duration and reason |
| `task.status` | a person changes a status from the dashboard or the CLI; names that person |

`task.finish` is written where the status is stored, not at each of the
orchestrator's exit paths, so an exit path added later can't miss it. A run
still in progress, or one whose hub died before it wrote a terminal row, shows
as `no terminal row` instead of being given an invented outcome.

### Retention: keeping the trail bounded

The trail only grows, and on a busy hub it grows fast: cloop's own control
plane reached 1.1M rows and 2.4 GB. Retention moves the oldest rows out of the
database without breaking verification.

Retention is **opt-in**. Without `audit.retention_days`, nothing is ever
pruned.

```yaml
audit:
  retention_days: 90            # 1–3650; 0 or absent keeps everything
  export_dir: /srv/audit-archive # default: .cloop/audit-archive
  prune_on_maintain: true       # let `cloop db maintain` apply it
```

A prune streams the oldest rows to a JSONL archive, verifies the chain of every
row on the way out, digests the file, and only then removes the rows. It
records an *anchor* holding the boundary hash, the id the chain resumes at, and
the archive's SHA-256. Unless forced, it never removes a row that an
[audit sink](#forwarding-the-trail-off-the-box) has not acknowledged: the prune
stops at the slowest sink's cursor and names that sink.

```console
$ cloop hub audit prune --before 90d --dry-run
$ cloop hub audit prune --before 90d
$ cloop hub audit anchors        # every truncation, oldest first
$ cloop hub audit verify-seals   # re-hash each archive against its anchor
```

After a prune, `cloop audit-log verify` uses the anchor to walk across the gap
and still reports OK. The anchor pins the id the chain must resume at, so
deleting a few more rows just past the boundary is still caught.

Three things to know:

- **Pruning doesn't shrink the file.** It frees pages onto SQLite's freelist.
  Run `cloop db maintain` to return them to the filesystem. That command runs
  `VACUUM`, which rewrites the whole file, so it refuses while any hub is
  serving the control plane. Stop the members (`cloop hub cluster status` lists
  them) or wait for the lease to lapse (`cloop hub lease status`).
- **`verify-seals` checks against something outside the database.** Chain
  verification can only prove that the remaining rows agree with what the
  anchors claim, and anyone who can rewrite `audit_events` can rewrite
  `audit_anchors` too. Copy the archives somewhere the hub can't write; that
  copy is your evidence.
- **A pruned trail can no longer be replayed from the beginning.**
  `cloop events replay` refuses to rebuild a partial database and names the
  archive holding the missing events. Pass `--allow-truncated` to rebuild only
  the remaining rows.

With `--verify`, export refuses a broken chain, so an exported file passed
verification at export time. Every format carries `prev_hash` and `row_hash`,
so the recipient can verify the file independently. Filters: `--actor`,
`--entity`, `--entity-id`, `--type`, `--since`, `--until`, `--limit`. Output
files are written with mode 0600.

Audit rows never contain credential material.
[Five separate checks](../security/model.md#secret-non-disclosure--secrets_testgo-audit_testgo-uiroutes_testgo)
test this, including one that scans every row rendering, not a sample.

---

## The git interception proxy

The proxy is off unless configured; `cloop hub bootstrap` turns it on with
`tls: auto`. With the proxy on, a sandbox that fetches and pushes the project's
source never holds the forge PAT. It gets a session token for a proxy the hub
runs, and the proxy enforces the branch allowlist on the ref updates in each
push. The design is in [git interception proxy](../git-interception-proxy.md);
this section covers running it.

### Turning it on

1. **Give it a certificate the sandbox will accept.** The sandbox's git
   validates the certificate, not the hub. The simplest option is `tls: auto`:
   the hub issues the certificate from its own CA, sealed under
   `CLOOP_SECRET_KEY`, and tells every sandbox it dispatches (host process,
   container, Pod, edge device) to trust that CA for the proxy's URL only, so no
   image needs changing. Otherwise use `cert_file` and `key_file`. A public-CA
   certificate needs nothing more. A self-signed or private-CA certificate needs
   its CA in the sandbox image's trust store, or in a bundle named by
   `SSL_CERT_FILE` / `GIT_SSL_CAINFO` on the machine git runs on. On Kubernetes
   the driver mounts the CA from a ConfigMap and trusts it for the proxy's URL
   only:
   [`executors.kubernetes.git_ca_bundle`](../reference/configuration.md#on-kubernetes-the-git-proxys-ca-for-its-url-only).
2. **Decide what the sandbox can reach.** `listen_addr` is the bind address.
   `advertise_url` becomes the sandbox's remote, so it has to be routable from
   where git runs: a Service for the Kubernetes backend, or the hub's address
   on the link for an edge device. The
   [table of forms](../git-interception-proxy.md#advertise_url-what-the-sandbox-can-reach)
   covers the rest.
3. **Write the section and restart the hub.**

   ```yaml
   executors:
     git_proxy:
       enabled: true
       tls: auto
       listen_addr: "0.0.0.0:8443"
       advertise_url: "https://hub.internal:8443"
       session_minutes: 60
   ```

4. **Confirm it came up.** One line on stderr names the bind address, the URL
   sandboxes are pointed at, and the allowlist. Under `tls: auto`, a second line
   describes the certificate:

   ```
   ui: git interception proxy on 0.0.0.0:8443, advertised as https://hub.internal:8443; pushes limited to refs/heads/cloop/**
   ui: git proxy serves a certificate the hub issued (tls: auto) for hub.internal, valid until …; sandboxes are told to trust the hub CA for https://hub.internal:8443 only
   ```

   From then on `cloop hub doctor` checks it: `gitproxy.tls` fails a leaf with
   less than a day left (the cluster leader renews it when two are left) or one
   that doesn't name `advertise_url`'s host. A failed renewal prints
   `ui: the git proxy's certificate could not be renewed: …`. A device whose
   agent speaks a protocol older than v21 is refused runs that would use the
   proxy, with an error naming the upgrade; upgrade it from the Executors
   panel.

5. **Run one task on the executor** and check the audit trail for the session and
   the fetch: `cloop audit-log list --entity gitproxy --since 1h`.

**With the Helm chart**, the steps above are values: `executor.gitProxy.enabled`
and a certificate from `executor.monitorTLS` (`auto`, `selfSigned`, or an
`existingSecret` from cert-manager plus a way for the Pods to trust its CA). The
chart advertises the proxy at the hub's Service name and adds the port to the
Pod and the Service. For a Secret it also renders `git_ca_bundle` with the CA
in a ConfigMap in the workload namespace. Under `auto` it renders nothing
extra, because each Pod gets the hub's CA from its run's lease Secret. See
[deploy/README.md](../../deploy/README.md#the-git-proxy-and-the-kubernetes-access-monitor).
CI runs a Pod through this configuration on a kind cluster on every push
([`tests/kube`](../../tests/kube/README.md)).

Two failure lines matter. Both mean GitHub access has stopped; neither opens it
up. After `ui: git interception proxy NOT started: …`, every git workspace that
needs a credential is refused with `ErrWorkspaceUnavailable`, and every GitHub
grant is left out of the leases it would have been part of, so it never
reaches the sandbox. `ui: executor <id> is NOT routed through the git proxy: …`
does the same to one executor's workspaces. The hub still starts in both cases,
so alert on these lines; a failed start won't tell you. A third line,
`ui: git proxy decisions will go to stderr, not the audit trail: …`, is less
serious: the proxy still refuses what it should, but the evidence isn't in the
database.

The most dangerous failure prints no `ui:` line at all. A section with
`enabled: true` that the configuration loader can't use (neither `tls: auto`
nor `cert_file` and `key_file`, or an unusable `listen_addr` or
`advertise_url`) is switched off at load with a
`warning: config executors.git_proxy.…` line. The hub then runs as if it had no
proxy, and credentials are delivered into sandboxes as before. After enabling
the section, look for the `ui: git interception proxy on …` line from step 4:
if it is missing, the proxy isn't running. See
[how it fails](../architecture/git-proxy.md#how-it-fails).

### Session lifetime is not run lifetime

A **workspace** session, the one cloop's own fetch and write-back use, lasts as
long as its run. It is minted for `session_minutes` (60 by default, 720 at most)
and, while the run lives, renewed by the same amount whenever five minutes or
less are left, with a `gitproxy.session_renewed` row each time. It is closed
once the run is done with it: after the fetch, or once the workload has
finished and its write-back has run. A run longer than `session_minutes` still
pushes its work back, and a run that ends early ends its session too. After a
restart, the member that adopts the run renews and ends the session. A member
on an older build only restores sessions that are still in their first period.
If such a member adopts a run whose session was renewed beyond it, the push
fails with an authentication error from git and a `gitproxy.rejected` row;
finish the upgrade.

A session minted for a GitHub **lease**, the one the workload's own git uses,
ends with its lease or after its own `session_minutes`, whichever comes first.
The lease ends when the run ends, when the lease is revoked from the Secrets
panel or with `POST /api/leases/{id}/revoke`, when the grant it was minted for
is revoked, and when the lease lapses. A run's lease is issued for 15 minutes
and extended in place while the run is live, so it only lapses when the run is
gone or a grant it holds was revoked or has expired. The janitor then sweeps it
within a minute, closing the session. Each extension is a `secret.renew` row; a
refused extension (because the grant was revoked) is a denied `secret.renew`
naming the grant. See
[how long a session lives](../architecture/git-proxy.md#how-long-a-session-lives).

A workspace session ends early when its lease is revoked. That lease is kept
alive while the session lives and is listed with the hub's other leases
(`GET /api/leases`, the Secrets panel); revoking it there closes the session at
once. A hub restart suspends a recorded session instead of closing it. That
covers a guarded session (the form a GitHub lease is delivered in) and a
workspace session whose lease is recorded, and the process that adopts the run
restores it (see [after a control-plane restart](#after-a-control-plane-restart)).
A session with no record is closed, as `gitproxy.session_closed` with the reason
*"the hub is shutting down"*. Otherwise a workspace session ends with its run
and a lease session with its lease, or either lapses at its deadline once
nothing extends it. The deadline is enforced at authentication, whether or not
the five-minute reaper has swept the session. Revoking the underlying grant
(from the Secrets panel or with `cloop secret revoke`) closes the sessions it
fed at once, on every hub member, and stops the next dispatch from minting
anything. Rotate the PAT at the forge as well.

The lease keepalive doesn't extend the GitHub App **token** a session presents
upstream, which GitHub accepts for an hour. The session renews the token itself,
at the grant's original scope, when about ten minutes are left. So with a
`github_app` grant, a lease session's life is capped by `session_minutes`, as
with a PAT, and a workspace session's by its run. See
[GitHub App tokens past their hour](#github-app-tokens-past-their-hour).

### GitHub App tokens past their hour

A `github_app` grant's installation token expires an hour after it is minted,
and the hub replaces it before then with a token of the same scope. With the
proxy, the session's request path does this; without it, the lease keepalive
does, rewriting the sandbox's `github-token` file in place. The full behaviour
is in [the secrets guide](../guides/secrets.md#keeping-the-token-past-githubs-hour).
If a long run loses GitHub access anyway, the cause is one of the following, and
the audit trail says which:

```console
$ cloop audit-log list --type secret.renew --since 24h --json      # re-mints, and refusals
$ cloop audit-log list --type lease.refresh --since 24h --json     # deliveries to the executor
$ cloop audit-log list --type github_app.token_destroy --since 24h # superseded and refused tokens
$ cloop audit-log list --type gitproxy.session_closed --since 24h  # sessions a refusal closed
```

| What you see | What happened | What to do |
| --- | --- | --- |
| a denied `secret.renew` naming a revoked or expired grant | the grant behind the token was withdrawn; its tokens were destroyed and, under the proxy, the session closed | nothing, if intended; re-grant otherwise |
| a denied `secret.renew` quoting GitHub (*suspended*, *not accessible to the installation*, 401) | GitHub refused the re-mint permanently: the installation was suspended or uninstalled, a repository was removed from it, or the App's key was deleted | fix the App installation, then start the run again |
| denied `secret.renew` rows saying *will retry* | GitHub was unreachable, rate-limiting or answering 5xx; the held token kept working while the hub retried each minute | check the hub's route to `api.github.com`; access ends only if this outlasts the token |
| a denied `lease.refresh` and a `credential_refresh` journal row naming the agent's protocol | the device's agent is older than v17, so it was not sent the new token; the run kept its first token until it expired | upgrade the agent to the hub's build (the row says how) |
| a denied `lease.refresh` naming `"patch"` | a Kubernetes executor's Role predates the `patch` verb on `secrets` | add `patch` to the Role's secrets rule (the shipped chart has it) |
| a denied `lease.refresh` saying the agent is not connected | the device was offline when the token was due | the keepalive retries each minute while the old token lasts |

A refresh doesn't cross members of a [hub cluster](#the-control-plane-lease). The
keepalive runs on the member that issued the lease and reaches only the agents
connected to that member. A device whose agent reconnected to another member
mid-run keeps its token until it expires.

### Alert on `gitproxy.push_denied`

```console
$ cloop audit-log list --type gitproxy.push_denied --since 7d
$ cloop audit-log list --entity gitproxy --since 24h --json
```

A `push_denied` row means a sandbox tried to move a ref outside its allowlist
(`refs/heads/main`, say) and was refused before anything was forwarded to the
forge. This row is the only record of the attempt, because nothing else in
cloop is on the push path.

A well-behaved task never produces one, so don't tune this alert away. Each
occurrence is either a workload doing something it wasn't asked to do or a
policy narrower than the task it was minted for, and both need a person to look.
The related `gitproxy.push_allowed` row is written *before* the forge's answer
is forwarded, so a `push_allowed` with no matching change on the forge means the
forge refused the push (branch protection, a non-fast-forward), not the proxy.

### Alert on `gitproxy.push_secret_refused`

```console
$ cloop audit-log list --type gitproxy.push_secret_refused --since 7d
```

Every push the policy allows is scanned on its way to the forge for the
credentials its run was given (`executors.git_proxy.push_scan`, `values` by
default; see [the push scan](../architecture/git-proxy.md#the-push-scan)). A
`push_secret_refused` row means a run tried to publish one. Its `findings` name
each object, its path and commit, and the grant and secret the value came from,
but never the value. The forge got no complete pack and no ref moved, so nothing
was published. The agent usually tries again, though, so look at the run's
history (a `git_push_refused` row) and the task's details, where the same
refusal appears as a line. A grant whose env secret holds values that aren't
secret (a region, a hostname) refuses any push that mentions them; take those
values out of the secret, or narrow the grant with `--env-keys`. A push refused
at a `push_scan_*` limit, or for a pack the proxy could not read, is a
`gitproxy.push_denied` row with `scan` set (`limit`, `unreadable`).
`cloop_gitproxy_push_scan_seconds` shows how close pushes come to
`push_scan_seconds`.

---

## The Kubernetes access monitor

The monitor is off unless configured; `cloop hub bootstrap` turns it on with
`tls: auto`. With the monitor on, a kubeconfig granted to a project stays in
the hub. The sandbox's `kubectl` gets a kubeconfig naming the monitor and a
session token, and each request is checked against the grant's verbs and
namespaces before the cluster credential is attached. A grant with no verbs is
read-only. The design is in
[Kubernetes access monitor](../architecture/kubernetes-access.md); this section
covers running it.

### Turning it on

1. **Certificate.** With `tls: auto` the hub issues it from its own CA, as for
   the git proxy (`cloop hub bootstrap` writes both). Either way, nothing has to
   change in the sandbox image: the monitor embeds its CA (the hub's, or
   `ca_file`, else `cert_file`) in every kubeconfig it issues.
2. **Reachability.** `advertise_url` becomes the kubeconfig's `server:`, so it
   has to be routable from where `kubectl` runs: the hub's Service, for Pods.
3. **Write the section** (`executors.kube_guard`; the
   [reference](../reference/configuration.md#kubernetes-access-monitor) has every
   key) and restart the hub, or with the Helm chart set
   `executor.kubeGuard.enabled=true` beside `executor.monitorTLS`.
4. **Confirm it came up:**

   ```
   ui: kubernetes access monitor on 0.0.0.0:8444, advertised as https://cloop-hub.cloop.svc:8444; policy floor no verb ceiling
   ```

5. **Check it from a sandbox.** Grant a project a kubeconfig with
   `--namespaces team-a` and no verbs, run a task, and look for
   `kubeguard.session_minted` and, when the task writes, a
   `kubeguard.request_denied`: `cloop audit-log list --entity kubeguard --since 1h`.

Its failure lines match the proxy's:
`ui: kubernetes access monitor NOT started: …` means kubeconfig leases are
refused, not delivered unguarded.

On every push, CI installs the Helm chart on kind with the monitor on, grants a
project a kubeconfig that can edit a namespace (with no verbs in the grant),
and runs a task. The task Pod's `kubectl get pods` is forwarded and its
`kubectl create configmap` is refused by the monitor. Both are audited, nothing
is created, and no cluster token is readable in the Pod. This runs on one
replica and on a hub cluster of three
([`tests/kube`](../../tests/kube/README.md)), and the same run tests the git
proxy.

### Alert on `kubeguard.request_denied`

```console
$ cloop audit-log list --type kubeguard.request_denied --since 7d
```

A task doing what it was asked never produces one, so each row is a workload
writing to, or reading outside, what it was granted, or a grant narrower than
its task. Allowed requests are recorded only when
`executors.kube_guard.audit_allowed` (in the chart,
`executor.kubeGuard.auditAllowed`) is on. Each forwarded request is then a
`kubeguard.request_allowed` row naming the verb, resource and namespace. Turn it
on where the trail has to show what a sandbox *read*, and expect a burst of
rows per `kubectl` invocation and one per watch.

---

## SCIM provisioning

The identity provider keeps the hub's directory up to date at `/scim/v2`, and a
person it deactivates is suspended without an operator
([guide](../guides/scim-provisioning.md)). Running it is mostly a matter of
noticing when it stops working, because a failing provisioning job only reports
errors at the provider.

`cloop hub doctor` checks it (`scim.config`, `scim.directory`). It reports a
live credential on a hub without single sign-on, which serves no `/scim/v2`,
and provisioned users who have no value for `ui.oidc.scim.match_claim` or share
one, so that deactivating them would reach nobody. `cloop hub scim status`
shows the credentials, when each was last used, and the same counts.

### Alert on `scim.user_suspend_incomplete`

```console
$ cloop audit-log list --type scim.user_suspend_incomplete --since 7d
```

The suspension's transaction committed (the person is denied, and their
sessions and tokens are gone), but a lease or a running task could not be ended
afterwards. The row's `warnings` say which. Revoke the lease under
**Secrets → Leases** and stop the task. A lease whose holder is unreachable
still lapses within 15 minutes, because its grant is suspended and can't be
renewed.

### Alert on `scim.match_ambiguous`

The provider deactivated a user whose match value is shared by more than one
hub identity. The hub denies the value itself instead of guessing which person
was meant, so everyone else with that value is refused too; that is the symptom
you will notice. Fix the mapping at the provider or choose a unique claim
(`oid`, `sub`). Then `cloop hub role list --identity` shows what the suspension
wrote.

### Watch `scim.request_refused`

A steady stream with `reason: unknown` or `revoked` means the provider's job is
about to be quarantined, usually after a rotation whose new secret never
reached the provider. `sso_disabled` means single sign-on was turned off on the
hub while the provider was still working, and `rate_limited` means a first
cycle larger than `ui.oidc.scim.rate_limit_per_minute`. A burst from an address
the provider doesn't use is somebody probing `/scim/v2`. Past five a minute,
SCIM's own lockout answers that address's wrong credentials with `locked_out`
(`429`), while the provider's valid credential is still served from the same
address. `unavailable` means the hub could not read the credential store; the
provider retries. The rows are rate-limited per minute, so their count is a
minimum.

---

## Key rotation

There are seven credentials, each with its own procedure in a subsection below:

- the TLS key rotates with a staged overlap;
- the dashboard token rotates by replacement, which causes a logout;
- an enrollment token or agent credential is revoked and the device re-enrolled;
- the sealing key rotates online with `cloop hub key rotate`;
- the hub's own CA rotates online, in stages, with `cloop hub ca rotate`;
- grants rotate by expiring;
- SCIM credentials rotate with an overlap.

The certificates the hub issues to its git proxy and Kubernetes monitor under
`tls: auto` need no procedure: they renew themselves two days before they
expire (see [the git interception proxy](#the-git-interception-proxy)).
`cloop hub key rotate` re-seals the CA's key, and a staged CA's, under the new
sealing key without reissuing either CA. Replacing the CA itself is
[its own procedure](#rotating-the-hub-ca).

### TLS certificate and agent pins — supported, staged

Agents pin the hub's **SPKI** (a hash of the public key), not the certificate.
A routine renewal that reuses the key doesn't change the pin, so an enrolled
fleet needs no action.

```console
$ cloop hub pin                          # from ui.tls.cert_file
$ cloop hub pin --cert /path/new.pem     # the pin of a certificate you are about to roll onto
```

Moving to a **new key** does change the pin. Stage the change; agents accept a
comma-separated set of pins so that the old and new pins can overlap:

1. Run `cloop hub pin --cert new.pem` to get the new pin.
2. Distribute `--pin <old>,<new>` to the agents and restart them.
3. Move the hub to the new certificate.
4. Confirm that `cloop executor ls` shows every agent reconnected.
5. Distribute again with only `<new>`.

Doing steps 2 and 3 in the opposite order locks every agent out.
`cloop hub tls-init` generates a self-signed certificate, for development only.

The [git proxy](#the-git-interception-proxy) has its own certificate, which the
steps above don't cover. Under `tls: auto` there is nothing to rotate by hand.
The cluster leader replaces each monitor's leaf certificate two days before it
expires, every member serves the new one within a minute, and sandboxes trust
the hub's CA, not the leaf, so a run in progress isn't interrupted.
`cloop hub doctor` fails `gitproxy.tls` and `kubeguard.tls` if renewal stops.
The CA itself is valid for ten years and is replaced only when an operator
rotates it, in steps that change what every new sandbox trusts before any
certificate changes; see [Rotating the hub CA](#rotating-the-hub-ca). With an
operator's `cert_file` and `key_file`, nothing pins the certificate, but every
sandbox's git validates it. A move to a new CA therefore has to reach the
sandbox image's trust store *before* the hub starts serving the new
certificate. Otherwise every provisioning fetch fails to verify the peer.

### Rotating the hub CA

Under `tls: auto` the hub issues its git proxy's and Kubernetes monitor's
certificates from its own CA, and every sandbox is told to trust that CA for
the monitors' URLs. The certificates renew themselves. The CA is replaced with
`cloop hub ca rotate`, online and in three steps, so that no sandbox is cut off
unexpectedly. Rotate it:

- when its key may have leaked (a backup taken together with the root key, a
  KMS identity used where it shouldn't have been, an operator who held either
  leaving);
- when `cloop hub doctor` reports it nearing expiry (`hubca.expiry`: a warning
  within a year, a failure within 30 days);
- before moving a monitor's advertise URL to a host the CA's name constraints
  don't permit (see below).

Settings → Hub health offers the same steps to an administrator without a shell
on the hub host.

```console
$ cloop hub ca rotate --status                    # where it stands: CAs, members, runs a step waits for
$ cloop hub ca rotate --stage                     # mint the new CA; every new sandbox trusts both
$ cloop hub ca rotate --status                    # the runs dispatched before the stage, still running
$ cloop hub ca rotate --activate                  # once none is left: certificates come from the new CA
$ cloop hub ca rotate --retire-previous --yes     # once every member serves them: the old CA is destroyed
```

**Stage.** The new CA is minted and sealed the same way as the first: under the
KEK registry (so under the KMS when `secrets.kms` is set), and rewrapped by
`cloop hub key rotate` like every other sealed key. Every hub member re-reads
its CAs within a minute (at once, when the cluster bus carries the step), and
every sandbox it dispatches from then on trusts both CAs: git's per-URL
`http.<url>.sslCAInfo` bundle, the kube monitor kubeconfig's
`certificate-authority-data`, the harness's `NODE_EXTRA_CA_CERTS` when its model
calls go through the relay, a Pod's lease Secret, and a device's or virtual
executor's start frame. The certificates still come from the old CA. Each
dispatch records which CAs it was told to trust on the spec its executor
session keeps (`executor.LabelHubCATrust`), and the next step reads that
record. The egress proxy needs nothing: it is a cleartext CONNECT proxy that
never installs a CA, and sandboxes reach the monitors directly, not through it.

**Activate.** The staged CA becomes the CA that certificates are issued from,
and the cluster leader reissues both monitors' certificates at once. Every
member serves them within a minute, and keeps serving the old CA's certificate
until then; every sandbox dispatched since the stage trusts both. (A member
whose leader has not reissued after three minutes reissues the certificates
itself.) `--activate` is **refused** while a run dispatched before the stage is
still running, because that run trusts only the old CA and would stop
verifying the monitors. The error names each run, with its project, task and
executor. Wait for them, or use `--activate --force --yes`, which breaks them
and records them on the rotation. Activation is also refused while a live hub
member has not adopted the stage, or runs a build that predates rotation. Such
a member would keep signing with the CA it opened at startup, so no flag
overrides this: upgrade or stop it. The command waits up to `--wait` (two
minutes) for every member to serve the new certificates and says which members
it is waiting for.

**Retire the previous CA.** Once every member serves certificates from the new
CA, `--retire-previous --yes` takes the old one out of every bundle and deletes
its row on a secure-delete connection. Its sealed key is then gone from the
database file, not left in SQLite's free space. Every write to `hub_tls` zeroes
what it frees, so no earlier copy of the row survives either (from a rewrap,
or from the activation that moved it). Retirement is refused while a stored
certificate or a member still serves a certificate from the old CA. Old pages
held in the write-ahead log last until the log is reused, and **a backup taken
before the retirement keeps the old key**, so take those backups again or
destroy them. Until you retire it, the old CA is what you roll back to, and nothing
else needs undoing.

`--abort --yes` destroys a staged CA that was never activated; every dispatch
that trusted it trusts the active CA too.

**An emergency: `--now --yes`.** If you believe the key is being used now, this
does every step at once. A fresh CA is minted (a staged CA is abandoned too,
because its key is in the same database) and activated, both monitors'
certificates are reissued from it, and the old CA is retired. The runs whose
dispatch trusted only the replaced CAs are named and recorded on the rotation.
Every hub member ends those runs' git proxy, Kubernetes monitor and model relay
sessions within a minute and records `hub_ca.sessions_ended`, because whoever
holds the old key could otherwise impersonate the monitors and take the session
tokens those runs present. Those runs fail from then on; restart them. The
command is refused while a hub member runs a build that predates rotation. A
leaked CA key usually means the sealing key or the database leaked with it, so
change the root as well
([Changing `CLOOP_SECRET_KEY` itself](#changing-cloop_secret_key-itself)) and
re-mint the credentials that root could open.

**Name constraints, and what moving an advertise URL involves.** A CA minted by
a rotation carries X.509 name constraints that permit only the names the
monitors are reached at: every name a certificate was issued for so far, the
configured `advertise_url` and `listen_addr` hosts, and each `--name`. git
already trusts the CA for the monitors' URLs only, but a harness's Node.js
trusts it for every host. Without constraints, whoever holds the key could
present a certificate for any host to a relayed harness; with them, Go, OpenSSL
and GnuTLS refuse it. `--no-name-constraints` mints a CA without them. The
constraints are part of the CA's certificate, so **moving a monitor to a host
they don't permit requires a rotation**. Without one, the certificate a member
would serve leaves the name out, every sandbox reaching the monitor by that
name refuses it, and `cloop hub doctor` fails `hubca.names`. Plan the move:
`--stage --name <new-host>` (the old names are kept), wait for the runs
dispatched before the stage, `--activate`, then change `advertise_url` and
restart the members. The CA a control plane minted at its first start has no
constraints; its first rotation adds them.

Two kinds of older component hold a rotation back. A device agent before
protocol v25 can't take two CAs for Node. A relayed run there is given only the
active CA, so it trusts only the old one and blocks the activation like a run
dispatched before the stage; upgrade such devices first. A hub member on a
build from before rotation also blocks it, as described above. Restoring a
backup taken before a rotation brings its CA back as the active one. Sandboxes
dispatched after the retirement don't trust it, and their runs fail until
restarted.

Every step is in the audit trail and in the
[metrics](metrics.md#the-hubs-certificate-authority). The audit actions are
`hub_ca.rotation_staged`, `hub_ca.rotation_activated` (naming any runs it was
forced past), `hub_ca.previous_retired`, `hub_ca.rotation_abandoned`,
`hub_ca.emergency_rotated` (alert on it) and each member's
`hub_ca.sessions_ended`. The metrics show the CAs' expiry, the phase, how long
the current step has lasted, and the runs and members it waits for.
`cloop hub doctor` warns when a stage has lasted longer than the longest
`session_minutes` a monitor grants (`hubca.rotation`), when a previous CA is
still trusted that long after its activation, and when a member predates
rotation or has fallen behind (`hubca.members`).

### Dashboard token (`CLOOP_UI_TOKEN`) — retire the old value, deploy a new one

It's better not to rotate it at all: once single sign-on works, retire it and
give each remaining caller a scoped API token (`cloop hub token create`).

To rotate it anyway, generate 32 random bytes, replace the value in `hub.env`
(or the Kubernetes Secret) and restart each member. A member accepts the value
it was started with, so both values work during a rolling restart. When every
member runs the new value, retire the old one so that every member permanently
refuses any copy left behind:

```console
$ cloop hub token static status                 # both fingerprints, which hubs hold which
$ cloop hub token static retire --fingerprint <old> --reason "rotated, CHG-2291"
```

Retirement is per value: a retired value is never accepted again, so the next
rotation needs a new value too. OIDC sessions are unaffected throughout.

### Enrollment tokens and agent credentials — revoke and re-enrol

```console
$ cloop executor agents                  # enrolled agents + outstanding tokens
$ cloop executor revoke <token-id|agent-id>
$ cloop executor enroll --name edge-1 --ttl 15m
```

Revocation cascades from the enrollment record to the credential derived from
it, and the hub sends `bye` with `reconnect=false` so the agent stops instead of
retrying. Enrollment tokens expire on their own (15 min by default, 24 h at
most). **Agent credentials don't expire**; revocation is the only way to end
one.

On a device running the installed service, you re-enrol by replacing the
credential file. The unit stays as it is:

```console
# on the device, as root
$ install -m 0600 /dev/null /var/lib/cloop-executor/enrollment
$ printf '%s\n' "$CLOOP_ENROLL_BUNDLE" > /var/lib/cloop-executor/enrollment
$ rm -f /var/lib/cloop-executor/agent.json      # drop the revoked identity
$ systemctl restart cloop-executor
```

The agent removes the enrollment file once it has redeemed the token, so an
empty `/var/lib/cloop-executor/enrollment` on a healthy device is normal. To
remove the device entirely, run
`cloop executor agent install --uninstall --purge`. It is idempotent, and it
checks afterwards that no unit, credential or state directory is left.

### Sealing keys — online, resumable, no credential re-minting

Stored credentials aren't encrypted under `CLOOP_SECRET_KEY` directly. Each row
gets its own random **data-encryption key** (DEK), which seals the payload, and
only the DEK is sealed under a **key-encryption key** (KEK) derived from the
passphrase. Rotation therefore rewraps sixty bytes per row and never decrypts a
payload, which makes it safe to run against a serving hub.

Several KEKs can be open at once. Rows move to the new one individually, and
reads keep working with whichever key each row still names, so nothing is ever
unreadable during a rotation.

```console
$ cloop hub key status                   # which key is sealing what
$ cloop hub key rotate --dry-run         # count what would move
$ cloop hub key rotate                   # mint a new KEK and rewrap onto it
$ cloop hub key list                     # keys, and whether each is still openable
```

`rotate` covers both kinds of long-lived sealed material, brokered secrets and
session refresh tokens, because they share one registry. Enrollment tokens and
agent credentials aren't covered and don't need to be: they are stored as
SHA-256 hashes, never sealed, so rotating a key can't affect them (see
[enrollment tokens](#enrollment-tokens-and-agent-credentials--revoke-and-re-enrol)).

**Interruption is safe.** After Ctrl-C, a restart, or a SIGKILL mid-write, the
row being written is protected by its transaction and everything else is
untouched, because rotation retires nothing and the old key stays usable. There
is no cursor to corrupt: the remaining work is "every row not yet under the
target key", so you resume by running the command again.

```console
$ cloop hub key rotate --continue        # resume onto the current primary
```

**Concurrent writes aren't lost.** Each rewrap is a compare-and-swap against the
ciphertext that was read. A credential re-minted, or a session refreshed, during
a rotation is left alone and counted as *skipped*; run `--continue` once
afterwards to pick those up.

**Run one rotation at a time.** Two concurrent runs each promote their own key
and move rows back and forth. cloop detects this (a row that keeps coming back
is reported, and the run exits incomplete instead of looping forever), but the
work is wasted. If you see `still not under ... after 5 attempts`, check for a
second `cloop hub key rotate`, then run `--continue`.

A hub that is serving while you rotate needs no coordination. It re-reads the
current primary key before every seal, so new material is sealed under the new
key from the moment it is promoted, and the hub starts using that key the first
time it needs it.

#### Retiring the old key — a deliberate second step

Rotation never destroys a key. Retirement does, and it can't be undone. It
blanks the KEK's salt so the key can never be derived from `CLOOP_SECRET_KEY`
again, and for a key [held by a KMS](#keys-in-a-kms) it destroys the KMS's
ciphertext of the key, so not even the KMS can give it back. Every write to the
key registry uses secure delete, so neither the blanked bytes nor an older copy
of the row from an earlier write stays in SQLite's free space. Old pages held in
the write-ahead log last until the log is reused, and a backup taken before the
retirement keeps everything. Anything still sealed under the key can't be
recovered after that, which is why retirement **refuses** while any row
references the key.

Retire a KMS-held key with this build or a later one. An older
`cloop hub key retire` (v0.0.6 and earlier) blanks only the columns it knows
about and leaves the KMS's ciphertext of the key in its row. A hub on this
build destroys that ciphertext at its next start, and the cluster leader at its
next KMS poll, and logs it
(`destroyed the KMS ciphertext … retired sealing key(s) still carried`).

```console
$ cloop hub key status                   # must report zero unrotated rows
$ cloop hub key retire <old-key-id> --yes
```

After retirement, reading material that still names that key fails with a
specific error, `sealing key retired`, naming the key and when it was retired,
instead of a generic decryption error. That tells you to re-mint the
credential, not to look for a passphrase problem.

#### Changing `CLOOP_SECRET_KEY` itself

Every KEK is derived from `CLOOP_SECRET_KEY`, so rotating KEKs limits the life
of each key but not of the secret they all come from. You can change that
secret online too. A hub holds a **current** root, which mints new KEKs and
opens existing ones, and, while a change is in progress, a **previous** root,
which only opens them. Nothing is re-minted at a forge or a cluster, and the
hub keeps serving throughout.

1. **Generate the new key** and install it alongside the old one on every hub
   member: the new key as `CLOOP_SECRET_KEY` (its file, credential or variable;
   see [the root key](#the-root-key)), and the old one as
   `CLOOP_SECRET_KEY_PREVIOUS` (`CLOOP_SECRET_KEY_PREVIOUS_FILE`, or the
   credential `cloop-secret-key-previous`).

   ```bash
   head -c32 /dev/urandom | base64 | tr -d '=' > /srv/cloop/cloop-secret-key.new
   ```

2. **Rolling restart.** Restart the members one at a time. Each starts on the
   new key with the old one alongside it (a hub starts only if every live KEK
   derives from one of its two roots) and advertises the new root's fingerprint
   in its cluster member row. Until step 4 the registry's primary key stays the
   old root's key, so restarted and not-yet-restarted members seal under the
   same key and can read each other's writes. Until then, you can back out the
   change by restarting with the old configuration.

   ```console
   $ cloop ui …
   Root key: de46939974158c63, from the file /srv/cloop/cloop-secret-key (CLOOP_SECRET_KEY_FILE)
   Previous root key: 7246e27af489f0e0, from the file /srv/cloop/cloop-secret-key.old (CLOOP_SECRET_KEY_PREVIOUS_FILE) — a change of root is in progress; finish it with `cloop hub key rotate --retire-previous` once every member runs on de46939974158c63
   ```

3. **Escrow the new key** with
   `cloop hub key escrow export --output <file off this host>`, in a shell
   holding both keys. Once the old root is retired, the new key is the only
   thing that opens this hub.

4. **Retire the previous root**, in a shell holding both keys:

   ```console
   $ cloop hub key rotate --retire-previous --dry-run
   $ cloop hub key rotate --retire-previous
   Change of root 7246e27af489f0e0 → de46939974158c63
     ready   member hub_cb87… (pid 4121 on hub-1): root de46939974158c63, previous 7246e27af489f0e0
     ready   member hub_50af… (pid 3880 on hub-2): root de46939974158c63, previous 7246e27af489f0e0
     ready   escrow esc_9d2c… holds the new key
     minted kek_b876… from the new root and made it primary
   …
   Every row is sealed under kek_b876…, and the previous root's 2 key(s) are retired: kek_42a9…, kek_8f0e….
   ```

   It **refuses**, and changes nothing, until every live member advertises the
   new key as its current root and an escrow of the new key is on record. A
   member still on the old key would be unable to read anything once the old
   keys are gone, and a member that advertises nothing predates the
   advertisement. It also refuses while a hub serves under
   `ui.cluster.exclusive`, which has no member row to advertise in; stop that
   hub for this step. Then it mints a KEK from the new root, rewraps every
   secret, session refresh token and hub CA key onto it with the same
   compare-and-swap rotation `rotate` uses, and retires every KEK of the old
   root. If it is interrupted, it retires nothing; run it again to continue,
   and it mints nothing the second time. A plain `cloop hub key rotate` during
   the change is refused, because it would mint from the new root without those
   checks.

5. **Drop the previous key** from every member and restart them again. `cloop hub
   doctor` warns (`secret_key.previous`) for as long as it is set. A member
   started with only the old key now refuses to start, naming the keys it can't
   derive. So does a member with a mistyped new key and no previous key.

**If the database leaked too, this is not enough.** A rewrap moves each row's
DEK under the new root's KEK, but it doesn't change the DEK, and every
payload's ciphertext stays as it was. Someone holding the old key *and* a copy
of the database from before the change can still unwrap the old DEKs, and those
open today's payloads. The change of root stops the old key from being used
from now on; it can't take back what a copy of the database already reveals. If
both leaked, re-mint the credentials at their sources as well:

1. Record what exists (never the values):
   `cloop secret grants --all > grants.txt`.
2. Rotate the underlying credentials at their sources (GitHub, cluster,
   registry).
3. Replace each stored secret with its new value: delete it (Settings →
   Secrets, or `DELETE /api/secrets/{id}`), `cloop secret mint` it again under
   the same name (a mint seals under a new DEK), and `cloop secret grant` it
   again from `grants.txt`.
4. Run `cloop secret lease --project <p>` to confirm delivery.

Session refresh tokens need no re-mint: sign everyone out
(`cloop hub session revoke --all`), and the next sign-in issues new ones.

#### Keys in a KMS

Everything above derives each KEK from `CLOOP_SECRET_KEY`, so the database and
the key file together open every credential: offline, from a backup, a volume
snapshot or a Pod's mounted Secret, for as long as anybody keeps the copy. With
[`secrets.kms`](../reference/configuration.md#sealing-keys-in-a-kms-secrets),
each KEK is random and the database keeps only the ciphertext a key-management
service made of it. Opening the store then takes a call to the KMS, which the
KMS logs, and the KMS owner can revoke the hub's access. The unwrapped KEKs
exist only in the hub's memory.

Two kinds of KMS:

* **A Kubernetes KMS v2 plugin** (`provider: kmsv2`), over a unix socket. This
  is the protocol the API server's own encryption at rest uses, so Azure Key
  Vault, AWS KMS, Google Cloud KMS and Vault are reached through the plugins
  their vendors already ship. In the Helm chart the plugin is a sidecar
  (`kms.*` values) on an emptyDir that only the Pod's containers can reach. On a
  host it is a service whose socket is in a directory only it and the hub can
  write; a socket in `/tmp` or `/dev/shm` is refused.
* **Vault or OpenBao Transit** (`provider: transit`), over HTTPS, authenticated
  by a token file (a Vault Agent sink) or Vault's Kubernetes auth method. The
  hub needs this policy on its key, and nothing more:

  ```hcl
  path "transit/encrypt/cloop" { capabilities = ["update"] }
  path "transit/decrypt/cloop" { capabilities = ["update"] }
  path "transit/keys/cloop"    { capabilities = ["read"] }
  ```

On Azure, `deploy/terraform/azure-entra-id/modules/key-vault-kms` creates the
Key Vault key (wrap and unwrap only, HSM-protected by default) and grants the
hub's identity *Key Vault Crypto Service Encryption User* on that one key; its
`helm_values_yaml` output is the chart's `kms` block for the AKS KMS plugin.

**Moving to a KMS** is a [change of root](#changing-cloop_secret_key-itself),
with the KMS as the new root and `CLOOP_SECRET_KEY` as the previous one:

1. **Add the KMS beside the passphrase** on every member and restart them one at
   a time:

   ```yaml
   secrets:
     kms:
       provider: kmsv2
       kmsv2: {endpoint: unix:///var/run/kmsplugin/socket.sock}
     previous_root: passphrase
   ```

   (With the chart: `kms.enabled=true`, the plugin's image and args, and
   `kms.movingFromPassphrase=true`.) Each member contacts the KMS before it
   serves, waiting up to `startup_timeout` for a sidecar that is still
   starting, and prints the result:

   ```console
   KMS: kmsv2:/var/run/kmsplugin/socket.sock, the KMS v2 plugin at unix:///var/run/kmsplugin/socket.sock, key key-3 (answered in 4ms)
   Sealing keys: held by the KMS kmsv2:/var/run/kmsplugin/socket.sock
   Previous root: 7246e27af489f0e0, from the file /etc/cloop/root-key/cloop-secret-key (CLOOP_SECRET_KEY_FILE), named by secrets.previous_root — a change of root is in progress; …
   ```

   Nothing moves yet. The primary key stays the passphrase's key, so restarted
   and not-yet-restarted members seal under the same key, and you can back out
   by restarting with the old configuration. `cloop hub doctor` reports
   `secrets.kms.reachable` for each member's KMS.

2. **Retire the passphrase's keys**, in a shell with the same `secrets` section:

   ```console
   $ cloop hub key rotate --retire-previous
   Change of root 7246e27af489f0e0 → kmsv2:/var/run/kmsplugin/socket.sock
     ready   member hub_cb87… (pid 4121 on hub-1): root kmsv2:/var/run/kmsplugin/socket.sock, previous 7246e27af489f0e0
     ready   the KMS kmsv2:/var/run/kmsplugin/socket.sock answers, encrypting under key-3; no escrow is needed for it — a restore
             of this hub needs access to that KMS key instead
     minted kek_9c21… from the new root and made it primary
   ```

   It refuses, and changes nothing, until every live member advertises the KMS
   as its root and the KMS answers. No escrow is needed, because no escrow can
   open what a KMS holds. Then it mints a KEK under the KMS (checking that the
   KMS unwraps it before anything is recorded), rewraps every secret, session
   refresh token and hub CA key onto it, and retires every passphrase-derived
   KEK.

3. **Drop `previous_root`** from every member and restart them. `cloop hub
   doctor` warns (`secrets.kms.previous`) until you do.

From then on, a copy of the database and the key file opens nothing. **Backups
taken before step 2 still open with `CLOOP_SECRET_KEY`**, because they hold the
passphrase-derived KEKs, salts included. Destroy them, or protect them as
carefully as the key. Moving between two KMSs is the same procedure, with the
old one as `secrets.kms_previous`. Moving back to the passphrase is
`secrets.kms_previous` with no `secrets.kms`, and the new passphrase then has to
be escrowed before the retire step will run.

**Rotating the KMS key** needs no action on the hub. Every member polls its KMS
once a minute. When the key the KMS encrypts under differs from the one a KEK
was wrapped under (a new Key Vault key version the plugin was pointed at, a
rotated Transit key), the cluster leader wraps that KEK again under the new
key, checks that it unwraps, swaps it into the record and records
`sealing_key.kms_rewrapped`. `cloop hub key rewrap` does this immediately. One
row per KEK changes, and no secret does. Disable the old KMS key version only
once `cloop hub key list` shows it on no live key, and never purge it while you
still keep a backup from before the rewrap.

**When the KMS doesn't answer**, nothing falls back to the passphrase:

* A starting hub refuses to start after `startup_timeout`, naming the KMS and
  what it said; `cloop hub doctor` reports `secrets.kms.reachable` failing.
* A serving hub keeps working with the KEKs it already holds in memory, logs the
  outage once, and polls every ten seconds until the KMS is back. A KEK it
  hasn't opened yet (one minted by another member in the meantime) can't be
  opened, and reads that need it fail as `kms_unavailable`
  ([metrics](metrics.md#the-key-management-service)).

**Revoking the hub's access at the KMS** (removing the role assignment, revoking
the Vault policy) stops every new hub process, every restore and every offline
copy from opening the store. A process already serving keeps the KEKs it holds
in memory until it exits, so to cut off a running hub, revoke access and then
restart its members.

#### Upgrading a hub that predates envelope encryption

Migration `0019_envelope_encryption.sql` marks every existing row `legacy` and
adds the new columns. It can't re-encrypt anything, because SQL can't decrypt.
Those rows keep opening under the old scheme until the first rotation converts
them:

```console
$ cloop hub key status                   # shows N rows as "pre-envelope"
$ cloop hub key rotate                   # upgrades them, once, permanently
```

Nothing breaks if you never run it, but until you do, rotation doesn't cover
those rows, and `status` keeps saying so.

### Grants — rotate by expiry, not by procedure

Short TTLs mean grants rotate themselves. See
[choosing TTLs](../guides/secrets.md#choosing-ttls).

### SCIM credentials — rotate with an overlap

The identity provider's credential for `/scim/v2` rotates in place, keeping its
name, so its audit actor (`scim:<name>`) doesn't change:

```console
$ cloop hub scim credential rotate entra --grace 1h --reason "yearly rotation"
```

The new secret is printed once, and the old one is still accepted for the grace
period (at most seven days). Paste the new one into the provider within that
time; with the Terraform module, set `scim_secret_token` and apply. Without
`--grace` the old secret stops working at once, and the provider's next cycle
fails with 401 until the new one is in place. Revoke a leaked credential
instead of rotating it: `cloop hub scim credential revoke entra --reason "…"`
ends both secrets immediately. See
[the credential](../guides/scim-provisioning.md#the-credential).

---

## The root key

The hub, and every command that seals or opens anything (the `cloop hub key`
commands, backup and restore, the escrow, the audit checkpoints,
`cloop secret`), reads `CLOOP_SECRET_KEY` through one resolver, `pkg/rootkey`.
Each of its two slots is read from three sources, in this order:

| Source | Current key | Previous key (a change of root only) |
| --- | --- | --- |
| a file | `CLOOP_SECRET_KEY_FILE=/abs/path` | `CLOOP_SECRET_KEY_PREVIOUS_FILE=/abs/path` |
| a systemd credential | `cloop-secret-key` in `$CREDENTIALS_DIRECTORY` | `cloop-secret-key-previous` |
| the environment | `CLOOP_SECRET_KEY` | `CLOOP_SECRET_KEY_PREVIOUS` |

**A key file** must be an absolute path to a regular file that the hub's user
owns, with mode `0400` or `0600`, outside every `.cloop/` directory. One
trailing newline is not part of the key. Anything else is refused, and the hub
doesn't start: a file another user can read or replace, a path through
`.cloop/` (even through a symlink), or an empty file. The hub accepts two kinds
of file it doesn't own, because Kubernetes and systemd create them that way. One
is a Secret volume's file, owned by root and readable by the Pod's `fsGroup`
and nobody else (mode `0440`). The other is the credential systemd 255 and later
hand to a unit with `User=`, owned by root and readable through an ACL entry
naming that user and nobody else. `stat` shows the credential as `0440` too, but
that is the ACL's mask: no group can read it. A root-owned file whose ACL also
lets another user or group read it is refused.

**Two sources that disagree are refused**; the hub never picks one. A key moved
into a file with a different key left in `hub.env` is two keys, and the choice
would decide whether the hub opens anything. Two sources that agree are fine,
but `cloop hub doctor` warns about a copy left in the environment, because that
copy keeps every exposure the file was meant to remove.

**Use the environment only as a last resort.** A variable shows up in
`/proc/<pid>/environ`, in `systemctl show`, in `docker inspect` and
`kubectl get pod -o yaml`, and in every child process it isn't removed from.
The doctor warns about one on a host that systemd runs. `cloop hub bootstrap`
writes a credential file instead, sealed with `systemd-creds encrypt` when the
host supports it (`--systemd-creds`), so reading it needs the host's credential
secret or its TPM. It also prints a unit that loads the file:

```ini
[Service]
EnvironmentFile=/srv/cloop/.cloop/hub.env
LoadCredentialEncrypted=cloop-secret-key:/srv/cloop/cloop-secret-key.cred
# or, unencrypted: LoadCredential=cloop-secret-key:/srv/cloop/cloop-secret-key
```

To move an existing hub's key out of `hub.env`:

1. Write it to a file:
   `umask 077; printf %s "$CLOOP_SECRET_KEY" > /srv/cloop/cloop-secret-key`.
2. Seal it if you want to:
   `systemd-creds encrypt --name=cloop-secret-key /srv/cloop/cloop-secret-key /srv/cloop/cloop-secret-key.cred && shred -u /srv/cloop/cloop-secret-key`.
3. Add the `LoadCredential(Encrypted)=` line to the unit.
4. Delete the `CLOOP_SECRET_KEY` line from `hub.env`, and restart.

The key is the same, so nothing else changes.

In a shell, point commands at the same file:
`export CLOOP_SECRET_KEY_FILE=/srv/cloop/cloop-secret-key`. A key sealed by
`systemd-creds` can only be read through systemd. Run the command under
`systemd-run -p LoadCredentialEncrypted=cloop-secret-key:<file> --pty …`, or
decrypt it to a 0600 file outside `.cloop/` for the duration of the operation.

The **Helm chart** mounts the Secret's `CLOOP_SECRET_KEY` at
`/etc/cloop/root-key/cloop-secret-key`, sets `CLOOP_SECRET_KEY_FILE` and
`CREDENTIALS_DIRECTORY=/etc/cloop/root-key`, and blanks the variable `envFrom`
would set. For a change of root, the only change the chart needs is adding
`CLOOP_SECRET_KEY_PREVIOUS` to the Secret.

A serving hub reads the key once, at startup, and prints where it came from:

```console
Root key: de46939974158c63, from the file /srv/cloop/cloop-secret-key (CLOOP_SECRET_KEY_FILE)
```

A key file that changes under a running hub takes effect at its next restart,
which is how a [change of root](#changing-cloop_secret_key-itself) is rolled
out. The fingerprint the hub prints is the one its cluster member row
advertises.

## Upgrade

Schema migrations live in `pkg/statedb/migrations/`, numbered from
`0001_init.sql`. They are embedded in the binary and applied automatically by
`statedb.Open()` on every start. Each runs in a transaction and records itself
in `schema_migrations`, with the version of the binary that applied it, so a
crash during a migration rolls back cleanly and the next start tries again.

**There are no down-migrations.** Migrations only go forward, which is why
step 1 below is required.

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
mounted, the ConfigMap arrived, and SQLite opened under
`readOnlyRootFilesystem` and `runAsNonRoot`. In production, pin the hub's own
image by **digest**, because nothing in cloop verifies the image the chart
deploys. The published hub images carry build provenance and an SBOM. Those the
publish workflow pushes for `main`, and for releases after v0.0.7, also carry a
keyless cosign signature from that workflow, so you can check one with
`cosign verify` before you deploy it. `sandbox.image_policy.require_signature`
applies to the images *projects* name for their sandboxes, never to the hub's
own.

Enrolled agents reconnect on their own backoff (1 s → 2 min). They don't need
upgrading at the same time, but check `cloop executor ls` afterwards. Confirm
that `cloop executor list` still shows the expected backends and that
`executors.allow_host_process` is still `false`. After every upgrade, check
that a configuration merge hasn't turned host execution back on.

Executor pools' controllers come after the hub. The upgraded hub serves its
new build's chart at `/charts/cloop-executor-controller.tgz`; apply the
ExecutorPool CustomResourceDefinition from that build, which Helm never
upgrades, then `helm upgrade` each controller's release with the hub's chart
and image tag. `cloop executor pool show <pool>` prints the command for a
controller that is behind the hub, and hub doctor warns
`executors.pools.protocol` until it is upgraded. See
[Upgrading](../guides/kubernetes-executor-controller.md#upgrading) in the
executor controller guide.

### Rehearsing a rolling upgrade

You upgrade a [hub cluster](../architecture/hub-cluster.md#operating-it) by
starting a member on the new build alongside the old ones and stopping the old
ones one at a time. Meanwhile two builds serve one database: the old members
tolerate the migrations they don't have and hand their runs over as they stop.
[`tests/upgrade`](../../tests/upgrade/main_test.go) rehearses this with the real
binaries (cloop's latest published release alongside the build under test) on
every push to main, in CI's *Upgrade rehearsal* job. The release workflow
rehearses it once more, from the previous release, against the binary it is
about to publish:

```console
$ CLOOP_UPGRADE_E2E=1 go test ./tests/upgrade/ -v -count=1 -timeout 12m
```

| Variable | Meaning |
| --- | --- |
| `CLOOP_UPGRADE_E2E=1` | Run it; without it, both scenarios skip and say so |
| `CLOOP_UPGRADE_MAIN_BIN` | The build under test; otherwise one is built from the checkout, stamped like the :8888 deploy (`dev+g<commit>`, its sequence on main) |
| `CLOOP_UPGRADE_FROM` | The release to start from; otherwise `releases/latest`, or, when the build under test is a release, the published release before it |
| `CLOOP_UPGRADE_CACHE` | Where release archives are cached, by tag (default: the user cache directory) |
| `CLOOP_UPGRADE_COSIGN` | The cosign binary, when it is not on `PATH` |
| `CLOOP_UPGRADE_KEEP=1` | Leave the scratch tree and every process's log behind |

**The release binaries are verified before they run.** The linux-amd64
archive, Sigstore bundle and `checksums.txt` come from the release's download
URLs. On every use, cached or not, the archive is checked against
`checksums.txt` and its bundle is verified with cosign against the release
identity that [`pkg/provenance`](../../pkg/provenance/provenance.go) pins (the
same check a device's installer requires) before the binary is extracted. The
binary must report the tag it was asked for. A cached archive that fails is
deleted and downloaded again. Without network access the scenarios skip,
naming the host they could not reach; CI requires both to have passed, by name.

**Forward: `TestRollingUpgradeFromTheLatestRelease`.** In one hub directory,
behind a load balancer, with single sign-on (a test identity provider, an
operator role mapping, deny-by-default), a token, and `--listen 127.0.0.1`:

1. The release builds a project and saves its tasks. Two release members serve
   it, an operator signs in, and the release's own agent enrolls through the
   load balancer.
2. The operator starts a device run, which a release member dispatches with a
   secret lease, a git proxy session and a Kubernetes monitor session (a GitHub
   App and a kubeconfig, each against a fake upstream). The release records CI
   exchanges and the run's quota counter.
3. A member on the build under test joins and migrates the control plane and
   both projects, recording each migration's verdict and the build that applied
   it. The release members keep serving.
4. Every column the build under test added, plus a column no build knows about
   on each table older builds rewrote (`plan_tasks`, `ci_exchanges`,
   `quota_counters`), is set in every row. Then release members write: they
   save a task, record a CI exchange, dispatch and settle a second project's run
   on the migrated database (taking its quota slot and giving it back), and use
   the build under test's session. Every row must keep what it held.
5. The release members are stopped one at a time, starting with the one holding
   the run. The run moves to the other release member and then to the build
   under test, which must hold its lease and both proxy sessions. The workload
   then pushes and lists pods through it.
6. The release's agent, reconnected to the build under test, must be listed
   online as an older build, not refused, with an Upgrade target its installer
   accepts. The run settles once, and its lease is released after the
   takeover.
7. Both audit chains verify against the checkpoints both builds sealed, with
   both the build under test's `cloop hub audit verify` and the release's.

**Backward: `TestRollbackToTheReleaseAfterMainMigrated`.** Once the build under
test has migrated a hub, the release must tolerate or refuse it as
[Rollback](#rollback) describes. The migrations actually applied are judged by
the verdicts recorded for them, and copies of the database with one more
migration recorded as `breaking`, unclassified, under an unknown verdict,
`additive` and `additive-columns` exercise every branch. A refusal must come
before the member binds its port or touches the membership and lease rows, in
the words the Rollback section shows for `cloop ui` and `cloop status` (the
test reads them from this page), with the release's `hub doctor` failing
`storage.schema`. `CLOOP_ALLOW_SCHEMA_DOWNGRADE=1` must open the database, with
`storage.schema_guard` failing.

It doesn't cover container or Kubernetes executors, releases from before the
hub cluster (v0.0.4 and earlier), or the device's own upgrade: the test checks
the Upgrade offer but doesn't press it.

**Last result: 2026-10-27, v0.0.7 → `dev+gba5e0984` (sequence 1179).** It
passed in CI on its first run (run 40565034886). The job took 132 s: 67 s to
build the commit and 47 s for the rehearsal step, which compiles the suite,
downloads and verifies v0.0.7 into an empty cache, and runs both scenarios. On
the development host the scenarios take 23 s once built (forward 17 s, rollback
6 s). Building the rehearsal found four defects, all fixed:

- The Rollback example on this page showed what `cloop status` prints, not what
  `cloop ui` prints. Since the hub cluster, `cloop ui` says
  `hubcluster: open <path>: statedb: …`, so an operator comparing a refused
  rollback with the runbook found a different sentence.
- Every command of a binary refusing a database printed the refusal twice, the
  first time as an `executor: handle persistence unavailable` warning about
  surviving restarts.
- The release's agent under a build of main was shown as a material "cannot be
  compared" version skew, although both builds carry their place on main. It is
  now shown as `older`, which on its own is not material.
- A run handed from member to member never gave its tenant's concurrency slot
  back. The member that dispatched it gave the slot back only when its own
  stream closed, which a stopping member never sees, and the member that
  adopted the run didn't know it held one. Every rolling update took one slot
  from every tenant with a run in progress, until a member started alone. The
  slot is now recorded on the run's owner row and given back by the member that
  settles the run. A run dispatched by a release from before this fix still
  keeps its slot; the rehearsal of v0.0.7 reports that instead of failing.

### Long-lived runs after an upgrade

An upgrade replaces the hub's binary, but not the runs the hub started. A hub
restart keeps them alive (the unit uses `KillMode=process`, and a restarted hub
adopts the runs it finds), so a run in auto-evolve, which never ends on its
own, keeps executing the build it started with for as long as it lives. On
2026-10-06 the run working on cloop's own repository was 132 builds behind the
hub serving it. As a result, "done means committed", switched on for the
project three days earlier, had never been enforced, and the disk floor was
inactive on a 98%-full disk.

**Seeing it.** When it starts, every run records its process and its build
(version, commit, sequence on main, the schema it embeds) in its project, as
the run-owner record, and journals it in the run's `session_started` row.
Anything that reads the project compares that record with its own build:

- the Overview's status line and the Tasks tab's run bar say
  *Running build dev+g4e35bf6, 132 builds behind this hub* while the run lags;
- `GET /api/state` carries `run_build` (`build`, `reference`, `behind`,
  `comparable`, `live`, `adoptable`, `pid`, `executor`), the `run_owner` record
  itself, `follow_builds`, and a pending `adopt_request`;
- `cloop status` prints `Build:    running dev+g4e35bf6 (sequence 831 on main)
  (pid 4242), 132 builds behind this cloop`;
- `cloop hub doctor` warns `runs.build_lag` for every `cloop run` on the host
  that is behind the doctor's build, or that never recorded one.

A run started by a cloop from before this record existed shows no build at all,
and the doctor says so ("has not reported its build"). Restart it once (Stop,
then Start), and from then on it can move to a new build by itself.

**Moving a run without stopping it** (host-process runs only):

```bash
# once, from the dashboard: the run's Overview → "Adopt at next task boundary"
curl -X POST -H "Authorization: Bearer $TOKEN" \
  "https://hub.example.com/api/run/adopt-build?project_idx=0"

# or for good: Overview → Active Options → Follow New Builds, or
cloop run --follow-builds          # stores the option with the project, then runs
```

The request needs the same permissions as Start (`run.start`, and the
executor's audience) and is audited as `run.adopt_requested`. It names the
run's process (pid, start time, boot id), so a run started later never acts on
it. The run acts at its next safe point: after the task in progress has been
settled and stored, and before the next task or evolve round starts. A parallel
run first lets its round finish and dispatches nothing new in the meantime. At
that point the run checks that no child process is alive, saves its state, and
validates the binary at the path it was started from
(`/usr/local/bin/cloop-latest` on :8888). `<path> version --json` must answer
within ten seconds with a `sequence` strictly greater than the run's own and a
`schema` at least as new as the project database's, and the new build must
accept the run's own command line (`<path> run … --help`). A request never moves
a run past the build of the hub that filed it. Follow New Builds waits until the
deployed file has been in place for three minutes: the deploy health-checks the
new hub for half a minute and puts the old binary back if that fails, and a run
that had moved within that window would have migrated its database beyond what
the rolled-back hub can open. The run then writes
`.cloop/run-handoff-<pid>.json` (run id, evolve iteration, the consecutive
failure and empty-evolve counters, its status and pause reason, and the reason
it moved) and calls `execve` with the same argv and environment plus
`CLOOP_RUN_HANDOFF`.

For the hub, nothing changes: the pid, the `(starttime, boot_id)` identity the
local driver checks, the hub's run claim and the live log's stdout pipe all
carry over. The new image journals `run_reexecuted` (old and new build, and
why), writes `run.reexecuted` to the project's audit trail, updates the
run-owner record (`reexecs`, `previous`), and continues the run. There is no new
`session_started`, no `--replan`, no `--retry-failed` reset, no `pre_plan` hook,
and no re-applied command-line toggles.

**When it doesn't move.** Every refusal is a `run_adoption` row in the event
history, with the reason, and the run carries on with the build it has:

| Journal says | Meaning | What to do |
| --- | --- | --- |
| `… is at the same sequence as this run's build` / `still holds the build this run is executing` | Nothing newer was deployed at the path | Wait for the deploy; check `/var/lib/cloop-latest/commit` |
| `… builds older than this run's build` | The path holds a rollback | Adoption never moves a run backwards; restart the run if you mean to |
| `… carries no sequence` | An unstamped build (`go build`) | Deploy a build stamped by the deploy script or `scripts/build-release.sh` |
| `… embeds schema N, behind the project database at M` | The deployed build is older than the database | Deploy a build at least as new as the schema |
| `` `version --json` failed `` / `did not answer within 10s` (`attempt N of 3`) | A broken binary, or a host too loaded to answer | Tried again at the next boundaries, three times per deployed file |
| `not an ELF executable` / `not a regular file` / `writable by its group` / `belongs to uid` | Not an installed binary | Fix the deploy; the next file at the path is looked at afresh |
| `does not accept this run's command line` | The new build dropped or renamed a flag the run was started with | Restart the run without it |
| `newer than the hub that asked` | The path holds a build the hub isn't running yet: a deploy in progress | Ask again once the hub runs it |
| `child processes are still running` | Something the run started has not exited | It retries at the next boundary (Follow New Builds) or refuses the request |
| `… executor, which keeps its own upgrade path` | A container or device run | Upgrade the device (Executors → Upgrade) or rebuild the image |

To confirm a move on the host: the pid in `cloop status` is the same,
`/proc/<pid>/stat` field 22 (the start time) is unchanged, and
`readlink /proc/<pid>/exe` names the deployed file instead of `… (deleted)`.

---

## Rollback

**An older binary can't open a database with a newer schema once the difference
matters**, and there are no down-migrations. cloop enforces this: an older
binary compares the database's recorded version with the highest migration it
embeds and, for every version it is missing, checks what that migration did.

Each migration is classified when it is applied, and the verdict is stored in
`schema_migrations.compat`. A migration that only *added* objects (new tables,
new non-unique indexes, new views) is `additive`: a binary that predates it has
no statement that refers to them, so their presence changes nothing it does.

Appending a column counts as additive too, under conditions that are checked:
the statement must be `ADD COLUMN`, the column must have a `DEFAULT` or be
nullable, and it must add no constraint (no `UNIQUE`, `PRIMARY KEY`,
`REFERENCES` or `CHECK`). This is safe because no query in `pkg/statedb` uses
`SELECT *`. Every read names its columns, so an older binary never sees an
appended column, and the default keeps the rows it inserts valid. A column that
is `NOT NULL` with no default is `breaking`, because every older `INSERT` would
fail on it.

Naming columns keeps an older binary's reads and inserts away from a new
column, but not a write that replaces a whole row. Releases before v0.0.5 (and
development builds from before 2026-10-06) wrote three tables that way:
`plan_tasks` (every save emptied the table and inserted the plan again),
`ci_exchanges` (`INSERT OR REPLACE`) and `quota_counters` (the gauge rows were
deleted and inserted again). Each such write resets every column the writing
binary doesn't know, so a build one migration behind erased that migration's
column on its first save. A column appended to one of those tables is therefore
recorded as `additive-columns`. v0.0.5 and later write those rows in place and
open the database. Older builds don't know the verdict, read it as unknown,
and refuse to open the database instead of erasing the column. Migrations
0001–0059 keep the verdicts they were recorded with: an older build that
predates one of their columns keeps erasing it until it is replaced.

Otherwise, a migration that altered, dropped or constrained something that
already existed is `breaking`. Anything unclassified (including rows written by
a build that predates this bookkeeping), and any verdict the reading build
doesn't know, counts as breaking.

A database whose extra migrations are all ones the binary can tolerate
(`additive`, and from v0.0.5 on also `additive-columns`) opens normally.
Otherwise the binary refuses, naming both versions, the build that moved the
schema forward, and the specific migrations that are incompatible. Development
builds from before 2026-09-12, older than every release, have no guard at all
and open any database. No verdict can stop them, so don't run one against a
database a newer build has migrated.

```console
$ cloop ui
Error: hubcluster: open /srv/cloop/.cloop/state.db: statedb: database schema is newer
than this binary: database is at schema version 30 but this binary carries 29 (applied
by cloop v0.4.0 as 0030_widget_policy.sql at 2026-05-02T09:14:22Z); … Incompatible:
0030_widget_policy.sql. …
$ cloop status
Error: statedb: database schema is newer than this binary: database is at schema
version 30 but this binary carries 29 (applied by cloop v0.4.0 as
0030_widget_policy.sql at 2026-05-02T09:14:22Z); … Incompatible:
0030_widget_policy.sql. …
```

`cloop ui` refuses while it joins the [hub cluster](../architecture/hub-cluster.md),
and names the database it could not join; every other command says the same
without that prefix. A migration recorded with a verdict the binary doesn't
know is listed with what was recorded, for example
`0060_widget_policy.sql (recorded "additive-columns", a verdict this build does not know)`,
which is what every build older than v0.0.5 says about that verdict. A
migration nothing classified is listed as `(unclassified)`. v0.0.7 and earlier
print the whole refusal twice, the first time as an
`executor: handle persistence unavailable` warning. The
[upgrade rehearsal](#rehearsing-a-rolling-upgrade) checks on every push to main
that the latest release prints these words.

The refusal happens before the hub binds a port or takes the control-plane
lease, so a rolled-back image fails its health check instead of serving from a
schema it only partly understands. Every command goes through the same path,
and `cloop hub doctor` reports it as `storage.schema` even when the hub can't
start. Run the doctor first when a rollback won't come up.

So a rollback means restoring a backup, not downgrading the database:

1. Stop the hub.
2. Install the previous binary or image tag.
3. `cloop db restore <backup taken before the upgrade> --force`
4. `cloop db verify`
5. Start the hub; check `/readyz`, then `cloop audit-log verify`.

### When the schemas are known-compatible

Purely additive gaps are handled automatically (see above). The override is
for the rest: a migration classified `breaking` that you have read and judged
harmless for your rollback, or one left unclassified by a build too old to
record a verdict. If you have checked the migrations between the two versions
and none of them touches what the older build uses,
`CLOOP_ALLOW_SCHEMA_DOWNGRADE=1` opens the database anyway:

```bash
CLOOP_ALLOW_SCHEMA_DOWNGRADE=1 cloop ui
```

Use it only for a rollback you have already thought through. Don't use it with
a build older than v0.0.5 to open a database whose extra migrations include one
recorded `additive-columns`: that build does open it, and its first write to
that table erases the new column. `cloop hub doctor` reports the variable as its
own finding, `storage.schema_guard`: a warning on its own, and a failure while a
skew is actually present. That way an override left in a Deployment manifest
doesn't outlast the incident it was set for. Unset it once the rollback is
over.

Everything between the backup and the rollback is lost: task state, audit rows,
grants minted in that window. If you can't afford that, export the audit trail
before upgrading:

```bash
cloop audit-log export --format jsonl --verify --output pre-upgrade-audit.jsonl
```

The `.pre-restore.<UTC>` file that restore leaves behind is your way back out of
a bad rollback. Don't delete it until you have confirmed the rollback is good.

---

## Fleet operations

```console
$ cloop executor list                    # registered backends and what they isolate
$ cloop executor ls                      # health, in-flight work, last contact
$ cloop executor test container          # preflight: run `cloop version` inside it
```

`list` shows the sandbox type of each executor, including `hypervisor-backed`
for one configured with a Kata runtime. `test` checks that it actually works: on
a Kata executor it also checks that the runtime name is registered with the CLI
and that `/dev/kvm` opens, then boots a real workload. See
[the Kata guide](../guides/kata.md#verifying-it).

Taking a node out of service:

```console
$ cloop executor cordon edge-01 --reason "kernel patch"   # no new work; running work continues
$ cloop executor drain  edge-01                            # no new work; wait for zero in-flight
$ cloop executor uncordon edge-01                          # back to whatever the probes justify
```

`uncordon` doesn't automatically mark the node ready. It returns the node to the
state its probes support.

On an edge device, `cordon` and `drain` also take back the leases the device
holds, with a scrub, as the dashboard's buttons do. The CLI doesn't contact any
device itself. It records the revocations, tells the running hubs over the hub
bus, and prints each member's answer (which member holds the device's
connection, and what happened to each lease) and the leases still pending. With
no hub serving, it says so, and the next hub to start takes the recorded leases
back when the device reconnects. Cordoning the hub's own container, Kubernetes
or host executor takes no credentials back.

If a node dies instead of draining, the supervisor handles it: three missed
heartbeats (~45 s) mark it `unreachable`, and its in-flight sessions are placed
on surviving nodes exactly once. See
[failover](../architecture/executors.md#failover-task-20162).

```console
$ cloop executor reap container          # remove sandbox containers/Pods left by earlier runs
```

`reap` takes an executor ID and acts on that one backend, not the whole fleet. A
hub reaps by itself at startup, so this command is for cleaning up after a hub
that is *not* running, or for a runtime shared with a hub that will never run
again.

### Moving a device onto the edge channel

A hub that runs an unreleased build of `main` (the reference deployment's
`dev+g<commit>`) can give its devices its own build, signed by CI, once a
device is on the [edge channel](../guides/edge-channel.md). Do this once per
device, on the device:

```console
# 1. cosign, which every build is verified with (a single static binary).
$ sudo install -m 0755 cosign-linux-amd64 /usr/local/bin/cosign

# 2a. A device whose cloop already knows the channel:
$ sudo cloop executor agent install --upgrade --channel edge

# 2b. One whose cloop predates it: fetch an edge build, verify it by hand, and
#     let it install itself — see the guide for the download and the cosign line.
$ sudo ./cloop executor agent install --upgrade --channel edge --to edge:<commit>
```

Installing onto the channel writes `20-update-channel.conf` next to the unit and
installs the remote-upgrade helper (`cloop-executor-upgrade.path` and
`.service`). Both survive later upgrades; only `--channel stable` /
`--remote-upgrade=false` on the device removes them. Check what the agent
reports about itself:

```console
$ journalctl -u cloop-executor -n 30 | grep -E 'updates:|firewall:|remote upgrade'
  firewall: nft(8) — CAP_NET_ADMIN held by the agent, never by its workloads
  updates: edge channel — releases, and signed builds of main
$ systemctl is-active cloop-executor-upgrade.path
active
```

If the path unit is inactive, upgrade requests are never read. The agent then
refuses upgrades and says so in its banner
(`remote upgrade: unavailable: … is not active …`) until you run
`sudo systemctl enable --now cloop-executor-upgrade.path`.

Then, in the dashboard, choose Executors → the device's **Upgrade** → *this
hub's build (`<commit>`)*. The device files the request, the helper verifies
and installs the build, and the device reconnects on it; the row's build chip
updates to match. On the device, the helper's journal shows the whole process:

```console
$ journalctl -u cloop-executor-upgrade
```

When the dialog doesn't offer the hub's build, it says why: an unpushed commit,
CI still running, CI or the edge workflow failed, the build was pruned, the
build would lower the protocol, or the device is already later on `main` than
the hub. The
[guide's table](../guides/edge-channel.md#upgrading-from-the-dashboard) gives
the fix for each. To go back: `/usr/local/bin/cloop.prev` is the previous
binary, `--to <release> --force` installs a verified release, and
`--channel stable` takes the device off the channel. Moving a device back to an
earlier build of `main` needs that `--force` on the device, because its
installer refuses an earlier build however the hub or its agent asks
([rollback protection](../guides/edge-channel.md#rollback-protection)). The
refusal is a `refused:` line in `journalctl -u cloop-executor-upgrade`.

**The hub's deploy builds the local `main`.** If it deploys a commit before the
commit is pushed, the dialog says so ("the deploy built commit … which is not
on GitHub"). The build is offered as soon as the push's CI run passes and
`edge.yml` publishes it, about half an hour later. A push of several commits
runs CI, and so publishes an edge build, for the newest commit only.

### After a control-plane restart

A hub killed mid-run doesn't lose the workloads it dispatched. The containers,
Pods and edge-device processes keep running, and on the next start each driver
reattaches to its own workloads from `executor_handles`. Whatever is left over
after that (session rows nothing will close, workloads nothing can reattach to,
worktrees nothing will merge) is cleaned up in the background with a two-minute
limit, so a git prune or a runtime listing never delays the listener. See
[durable handle identity](../architecture/executors.md#durable-handle-identity-task-20191).

The sweep reports what it did in the hub's normal log, prefixed `ui:` under
`cloop ui` and `apiserver:` under `cloop serve`. The lines to recognise:

```
executor: 3 in-flight session(s) reattached to a still-running workload
executor: closed 1 stale in-flight session(s) left by a previous control plane (drain would otherwise have waited on them forever)
executor container: garbage-collected 2 exited container(s) from a previous run: cloop-app-a1b2, cloop-app-c3d4
executor container: killed 1 container(s) still running from a previous control plane: cloop-app-e5f6
executor: pruned 2 leaked task worktree(s) in /srv/app: worktree gc: removed 2 worktree(s) and 0 branch(es); kept 5; 0 error(s)
```

**"reattached" is the line you want.** Those runs survived the restart: their
output continues in the dashboard and their exit codes are still collected.

**A Kubernetes run that fails with *"the per-run Secret … no longer exists"*** had
its harness container held by the kubelet in `CreateContainerConfigError`. The
harness reads its whole environment from the run's `cloop-lease-<handle>` Secret
when the kubelet creates the container, and that Secret was gone. A hub doesn't
delete it before the harness has started, so the usual cause is outside cloop
(an operator or a cleanup job deleting Secrets in the workload namespace), or a
hub older than v0.0.5 restarting mid-fetch. The run is failed instead of left
pending, and its Pod is deleted; dispatch the task again. The same failure one
container earlier names `cloop-ws-<handle>`, the workspace credential.

**An edge device's run is adopted when its agent reconnects.** The sweep runs
before any agent has reconnected, so it leaves a device's session open instead
of closing it as failed. When the agent reconnects, the process it reaches
adopts the run
(`adopting a run from another hub member … reason="its agent reconnected to this hub member"`)
and takes over the run's secret lease, logging one
`took over the secret lease of an adopted run` line per lease. From then on
that process owns the run: it streams it, merges the device's result into the
project once, keeps the lease alive, releases it when the run ends, and closes
the session with how the run ended. If a lease lapsed while the hub was down
(for longer than the lease had left, which the keepalive keeps between about
five and fifteen minutes), or its grant was revoked in the meantime, the lease
is scrubbed from the device instead (`lease.revoke_sent` by `janitor`), and the
run carries on without those credentials. A run whose agent never comes back
keeps its session open for failover, and keeps its lease until the lease lapses
and the leader's lease janitor sweeps it.

**What the lease feeds comes back with it.** The adopting process restores the
run's git proxy and Kubernetes monitor sessions under the ids and tokens the
workload already holds, logging one line each:

```
ui: restored git session 3K2x… of lease lease_9f1c…, held until then by hub_7d0e…
ui: restored kube session qT8w… of lease lease_9f1c…, held until then by hub_7d0e…
```

and writes a `gitproxy.session_restored` / `kubeguard.session_restored` row. A
GitHub App token behind the git session is minted again at the scope recorded
for it (an allowed `secret.renew` row: *"re-minted at the scope recorded for it
by the hub process that took the lease over"*), and the new process's keepalive
renews an App token the workload holds as a file before its hour is up. The
run's egress session is restored too, with its byte counters; the project's
journal says *"egress: proxy session … restored by the hub process that adopted
this run"*. A request the workload makes in the seconds before its agent
reconnects waits up to 60 seconds for this instead of failing.

A session that doesn't come back says why on its close row: a
`gitproxy.session_closed`, `kubeguard.session_closed` or `egress.close` whose
reason starts *"not restored by the hub process that adopted its run"* (its
grant was revoked or expired while the hub was down, its recorded scope is
wider than the grant or the proxy's policy now allow, its record names an
upstream other than the forge this hub's git proxy fronts, or this hub runs no
such proxy), or *"lapsed … while no hub process held it"*. This hub never
writes a record naming another upstream, so treat one as a sign the database
was edited, and check who could write to it. From then on the workload gets a
401 (git, kubectl) or a 407 (egress); stop and start the run to get a new
lease. A line ending *"(will retry)"* is a restore that failed for a reason
that may clear (the database busy, GitHub unreachable for the App token). The
lease's keepalive retries it every minute (an egress session after two seconds,
with the wait doubling up to a minute), and a request presenting the session
retries it at once. Count them with
`cloop_proxy_session_restores_total{kind,outcome}` (see
[metrics](metrics.md#sessions-restored-with-an-adopted-run)).

**A takeover the store cannot decide is tried again.** Taking over the lease can
end undecided: the secret store unreadable for a moment, the database locked,
the disk at its floor, or a KMS down for a process that hasn't opened the store
yet. The adopting process logs this,

```
ui: take over lease lease_9f1c… of the run on edge-1 (will retry): secretbroker: take over lease lease_9f1c…: read its revocations: … database is locked
```

and keeps trying: after two seconds, then with the wait doubling up to a
minute, until an attempt decides it or the lease's recorded expiry passes.
Meanwhile:

- the lease stays listed in the run's owner row, next to an entry saying its
  takeover is undecided, so a process that adopts the run after this one tries
  too;
- the run's event history has a `lease_takeover` row: *"The run's secret lease
  … could not be taken over by the hub process that adopted this run (…): …. It
  is tried again until it lapses at …"*;
- `cloop hub doctor` and Settings → Hub health warn
  [`runs.lease_takeovers`](#doctor-runs), naming the run, the lease, the
  attempts and the reason, and `cloop_lease_takeovers_total{outcome="retrying"}`
  counts the attempts;
- a request the workload makes waits up to 60 seconds, as it does before the
  adoption, and brings the next attempt forward.

Fix what the doctor's other findings name: the storage checks, and
`secrets.kms.reachable` for a KMS that doesn't answer. The next attempt then
takes over the lease and restores what it feeds, and a second `lease_takeover`
row says it *"was taken over … after N attempts"*. Nothing needs restarting. A
lease still undecided when it lapses, or when its run ends, gets a final row
saying it *"was never taken over"* and why, and counts as `failed`. The run
carried on without it, and its git pushes and kubectl calls through the hub
were refused, so stop and start the run to get a new lease. The run's workspace
lease and its egress session are retried the same way. On v0.0.7 and earlier
the stderr line is all there is: the lease drops off the owner row, nothing
extends it, and the run's next push fails with nothing on the run saying why.

**A device workspace's pinned session comes back too**, when the device keeps
it for a push write-back (`executors.write_back: push`). The run's owner row
names its workspace lease, which the adopting process takes over (one
`took over the workspace lease of an adopted run` line), and the session is
restored like the lease's, with the same `restored git session …` line. Its
upstream is the project's own `origin` as the hub's checkout currently names
it, so a record whose repository no longer matches is refused with *"it is
pinned to …, and the project's origin is … now"*. The device's write-back push
then succeeds whenever it arrives, and the project's journal records it as a
`write_back` row naming the branch.

**A Pod's workspace session comes back too**, whether or not the run pushes its
work back. A Pod's init container fetches its workspace after the dispatch, so
its session matters from the start. The run's owner row names the Pod's
workspace lease and session. The adopting process logs the same `took over
the workspace lease of an adopted run` and `restored git session …` lines, and
an init container that fetches after the restart is served. Once the Pod's
fetch is confirmed, the session is closed (*"the run is done with its workspace
credential"*) and the lease released; under `write_back: push` both last until
the workload ends. A fetch made before the adoption waits for it, for at most a
minute. On a hub whose leader is being replaced, the adoption can take longer
than that, and the Pod then fails its provisioning; start the run again. See
[limits that remain](../architecture/git-proxy.md#limits-that-remain).

**A CI relay session is restored by the next call that presents it**, not by an
adoption, because no run or lease stands behind it. A hub stopped gracefully
writes a `ci.session.suspended` row per live session. The job's next call to
any hub process restores the session, with a `ci.session.restored` row whose
`detail` names the process that held it and anything its rule narrowed. A
session whose rule was deleted or disabled, or no longer admits its pipeline,
gets a `ci.session.closed` row instead (*"not restored by the hub process that
received its next request: its rule is disabled"*), and the job gets a 401. A
session killed with its hub may be missing up to its last 15 seconds of spend.
The **Live sessions** panel lists a session no process serves as *suspended*;
**Revoke** there ends it before its job calls again. A revocation, rule edit or
switch-off that ends a record another member serves, or one a member is
restoring at that moment, reaches that member at its next checkpoint, within
15 seconds; the API has already answered by then. A **Revoke** answered with
`503` (*"its record could not be closed"*) ended the session on the member that
answered but left its record open, so another process could still restore it.
Revoke it again.

**Switching CI federation off applies per hub instance**, that is, per
`cloop ui` port, whose
[overlay](../reference/configuration.md#two-dashboards-in-one-directory) can
set `ui.ci.enabled`. Each session's record names the instance that served it.
When an instance's configuration turns federation off:

- **The process serving it** ends its sessions: at once through Settings,
  which also tells the other members to re-read their own configuration, or
  within 15 seconds when the file is edited.
- **Its suspended records** end at once through Settings, and otherwise
  within a minute. The leader reads every instance's configuration the way
  that instance does, since the overlays live in the hub's directory, so
  this happens whether or not the instance is running. Before then, a
  restore refuses such a record (*"federation is switched off on the hub
  instance that served it (port …)"*).
- **An instance that keeps federation on** keeps its records.

So:

- **To stop every pipeline at once** in a cluster whose overlays differ,
  disable or delete the rules. That closes their records wherever they are
  held, and members drop the sessions within 15 seconds.
- **A quick off-and-on** ends only what was noticed while it was off. Every
  relay call is refused while it is off, whichever member receives it.
- **A record a live member took over but could not restore** stays until it
  lapses or its rule changes. It is restored only under its rule as the rule
  stands then.

**Read "killed N container(s) still running from a previous control plane"
carefully.** It means a sandbox was *executing a harness* when it was
collected, so work in progress was destroyed. It is worded differently from the
"garbage-collected N exited" line so you can tell the two apart in a log. It
only fires for a container older than the
[grace period](../reference/configuration.md#container-sandbox) that carries
this executor's own labels and that no live handle claims, and after a healthy
restart there should be none: rehydration adopts what it can, so anything
reaped was dispatched by a process with no handle store, or one whose rows were
lost. If you see it routinely, handle persistence isn't working. Check the
startup log for `handle persistence unavailable`, which names the reason and
warns that workloads dispatched by that process won't survive a restart.

`localprocess` is the driver that recovers least, and you see that in the run's
own log, not the hub's. A host workload that survived a restart has a `[cloop]`
line saying its live output was lost with the pipe that carried it, and that
the process is still being watched. A workload whose pid was recycled, or whose
host rebooted, is reported `failed` with exit code `-1` and a message saying
which. The hub can't collect the exit status of a process that isn't its own
child, and reporting `exited(0)` would mark failed work as done.

### A drain never finishes

`cloop executor drain <id>` (and the dashboard's drain button) waits for the
executor's in-flight session count to reach zero, and gives up with
`ErrDrainTimeout`. A hub that restarted while a run was in progress used to
leave a `running` row in `executor_sessions` that nothing would ever close, so
drain timed out on that executor every time: the count never moved, however
long you waited.

The startup sweep closes those rows, so first try restarting the hub: it closes
rows whose executor no longer knows the handle. If drain still hangs after
that, the count is real. The sweep leaves a row alone when it can't tell
whether the workload is running: `sessionOutcome` treats a driver that can't
answer (an unreachable cluster, a device that hasn't reconnected) as *live*,
because closing a session whose workload is actually running would let the
scheduler place its task again and put two agents in one repository. Check the
executor's health with `cloop executor
ls` and fix the reachability. `--force` stops *waiting* instead of failing: the
node stays draining, and the sessions it reports are still running and
untouched.

### A project is paused because its executor was lost

The project's status badge reads "executor lost", with the executor named in
the reason. Its executor stopped answering mid-run (after about 1½–3 minutes of
failed probes) and the hub failed the run over: the tasks it was running went
back to pending (or failed; see below), and nothing continued the run, for the
reason the badge gives:

| The reason says | What it means |
| --- | --- |
| no executor could take the run | No other healthy executor could take it: a single-device project, or every other executor is down, cordoned, or restricted to an access list. (A failover never moves a run onto such an executor, and never moves an isolated run onto the hub's own host.) |
| failover gave up after N re-dispatches | The run had already been failed over as often as `executors.failover.max_attempts` allows. The task it was on failed, naming every node it was lost on. |
| task N is quarantined as a suspected node killer | Two executors went down under that task; see below. |
| the replacement on X could not start | The replacement was refused as any run would be. The Event History row says why (no Claude credential granted for X, a sandbox X can't honour, …). |

A replacement refused because it could not act for the person who started the
run is paused as *starter's Claude account unavailable* instead; see the next
section.

The Event History has a `failover` row saying "Executor X was lost …" with the
full reason. To continue, bring the executor back or bind the project to
another one, and press Run for an ordinary dispatch. If the device does come
back, it is told to terminate the run it was carrying: that run's tasks are
already back in the plan, and its credentials were released when it was lost.

A project whose run *was* failed over keeps running on the replacement. Its
Event History says "Run failed over from executor X to Y", the live log marks
where one run ended and the other began, and Stop stops the replacement.

### A paused run is not resumed: its starter's Claude account is unavailable

The status badge reads "starter's Claude account unavailable", naming a person.
The run had stopped at a usage cap whose window has reopened, or its executor
was lost and another could take it. The hub normally continues both kinds of
run by itself, but on a hub with single sign-on such a run acts for the person
who started it, on their own Claude account, and the hub could not act for
them:

| The reason says | What it means |
| --- | --- |
| has no Claude Code login on this hub that the hub may use for them | Their Claude home is gone (an offboarding removed it) or they never signed in here, and the run would share the hub's filesystem, where it uses that home. Or the hub denies them: a deny binding on them, hub-wide or on the project, or a deactivation at the identity provider. The hub's log says which (`auto-resume: held`, or `ui: failover of …`); the project's reason never does. |
| may not use the executor this project runs on | the executor is restricted to an access list whose entries all name people by email (or all by subject) and none of them is the starter, so their own Run would get a 403. Add them, or press Run as someone on the list |
| nobody is recorded as having started this run | a run older than the record of its starter, in a project with no owner |
| this run was not started from this hub | the paused run recorded itself (`run_owner`) well after the hub last dispatched the project (a `cloop run` from a shell), so whoever last pressed Run here is not the person it acts for |
| nobody could be named as having started this run | a resume carried such a run on where no Claude home was needed, or the hub's two records of the starter disagree because an older hub build dispatched the project since |
| … whose usage could show the window reopened | an older build's extra-usage pause, which clears by the starter's own usage windows, for a starter with no home here to read them under |

If the hub can't read the control plane at that moment, it refuses the resume
without holding the run: the pause stays a usage cap, and the next sweep tries
again.

The project's Event History has the full sentence: a `session_paused` row
("Auto-resume held: …") for a resume, and a `failover` row for a lost executor.
This pause can't be resumed automatically, so the sweep leaves it alone. To
continue, press Run; the run then acts for you, on your own account. Hubs
before v0.0.7 restarted such runs with the `cloop ui` process's own
environment, the shared login that per-user mode exists to remove.

To see whom a project's next resume would act for, read the control plane
(read-only):

```bash
sqlite3 -readonly .cloop/state.db \
  "select key, value from metadata where key like 'hub.harness.initiator.run:%'"
```

Each value names the person (`identity`), how they were chosen (`basis`:
`starter`, `owner` or `unknown`) and the run it describes (`run_id`). An empty
identity on the `starter` basis is a run started on behalf of no one (by the
static bearer token or a service token), which resumes on the hub's own login,
as it started. Builds before v0.0.7 kept only the bare identity, under
`hub.harness.initiator:<project>`, and it is still written alongside the record
for them. Each `run.cap_resumed` audit row names whom that resume acted for
(`acted_for`, `acted_for_basis`), and each placed `executor.failover` row names
whom the replacement acted for.

### A task is quarantined as a suspected node killer

Two or more executors became unreachable while one task was running, so the
hub's failover failed the task and marked it. It won't run again, on the next
dispatch or under retry-failed, until somebody resets it. To list such tasks,
with the nodes that went down under each:

```bash
cloop executor list --inventory    # "Suspected node killers", per project
```

The task's details in the dashboard say the same, and the project's Event
History has a `failover` row for each lost node. Before releasing the task,
find out why those nodes went down. A device's own journal (`journalctl -b -1`
after a reboot, the kernel's OOM and panic lines) usually names the cause, and
a task that exhausted memory on two devices will do the same on a third. Two
unrelated node failures can mark an innocent task, which is why a person has to
clear the mark.

To run it again, reset it from the task's status control in the dashboard, or
in the project's directory:

```bash
cloop task reset <id>
```

The reset deletes the mark and the recorded losses behind it, so the task
starts with a clean record. The reset is recorded as `task.quarantine_release`
with who did it. The run the task was in was not re-dispatched when the task
was marked, so the project is paused with an `executor_lost` reason. Press Run
once the task is reset, or leave it held: the gate skips a held task and runs
the rest. A run that loses more nodes than `executors.failover.max_attempts`
allows stops being re-dispatched whether or not any task is marked; its
journal row names every node it lost.

### Pruning leaked worktrees by hand

In parallel mode, each task gets a git worktree under
`.cloop/worktrees/task-<id>` on a `cloop/task-<id>-<slug>` branch. A run killed
between creating the worktree and merging it leaves both behind. On its next
start the hub removes those *directories* that are older than two hours,
skipping any task it believes is still running. It never touches a branch,
because an unmerged branch is the only copy of that task's work.

```console
$ cloop worktree list                              # what is on disk, what git knows, and how old
$ cloop worktree prune --dry-run                   # the plan, including the branches it would keep
$ cloop worktree prune                             # remove directories older than 2h
$ cloop worktree prune --delete-branches           # …and merged cloop/task-* branches
```

Run these from inside the repository; both act on the current working
directory. `list` shows two kinds of leak that a sweep looking at only one
source would miss: a directory git no longer registers (`GIT` `no`), and a
registration whose directory is gone (`DIR` `no`).

`--min-age 0` turns off the age check and is the only flag here that can
destroy work: a live parallel run's worktrees are in that directory right now,
and git can't restore what was never committed. Use it only when you have
confirmed that nothing is running. `--delete-branches` is safe in comparison.
It deletes only branches already contained in the base branch (`--base`,
defaulting to the checked-out one), the check is made twice, and
`git branch -d` itself refuses to delete unmerged work. A branch reported as
kept because it "is not merged" holds the only copy of a task's work, so cloop
won't delete it; merge or delete it yourself.

A non-zero exit from `prune` means some worktree could not be removed (a
permission error, a busy mount), and the output names it. The others were still
removed.

A worktree **locked** with the reason `cloop: kept for the task's next attempt`
is not a leak. Under [done means committed](../guides/done-means-committed.md),
an attempt that left its changes uncommitted (or stopped before it finished)
keeps its worktree for the next attempt at the task, which reopens it. Neither
`prune` nor the startup sweep touches a locked worktree. If the task will never
run again, look at what it left (`git -C <path> status`), keep what you want,
then run `git worktree unlock <path>` and prune.

---

## Incident playbooks

### Access emergencies

Sequences you can paste. They are CLI commands, not only dashboard
actions, because you may need them when a browser won't help: the listener is
stuck, you are on the host over SSH, or the account you need to contain is the
one that would do the containing.

Every command that changes something requires `--reason` and records it in the
hash-chained audit trail along with the OS user who ran it, so
`cloop audit-log list` shows who did what, when and why. Read the entries back
with:

```bash
cloop audit-log list --entity session --since 24h
cloop audit-log list --entity role_binding --since 24h
cloop audit-log list --entity quota --since 24h
```

#### An open hub is reachable from the network

`cloop hub doctor` fails `ui.exposure` with *a hub without sign-in listens on
\*:8080 (GET /api/projects … answered 200 without credentials)*. Anyone who can
reach that port can list the projects and start agent runs on the host, so
close it first and investigate afterwards:

```bash
# 1. Close it, either way:
systemctl stop cloop-ui                                   # the unit serving that port
iptables -I INPUT -p tcp --dport 8080 ! -i lo -j DROP     # or keep it, loopback only
ip6tables -I INPUT -p tcp --dport 8080 ! -i lo -j DROP
# 2. What did it do while it was open? Projects, runs and tasks it was asked for:
cloop audit-log list --since 72h
# 3. Restart it with a build that defaults to loopback, or give it sign-in
#    (ui.oidc, or CLOOP_UI_TOKEN) before it listens on the network again.
#    Retire a static token once SSO works: `cloop hub token static retire`.
```

The finding names the cause when it can: *this build would listen on
127.0.0.1:8080, so the process on the port is an older build or was started with
--listen*. A binary from before the loopback default binds every interface
whatever its configuration says, so only stopping it, or the firewall, closes it.

Then check what forwards to the port. A reverse proxy on the same host that
passes requests to the hub without authenticating them (an nginx
`proxy_pass http://127.0.0.1:8080` with no `auth_request` or `auth_basic`)
exposes the hub whatever it binds and whatever the firewall drops on 8080, and
the doctor can't see it. Test through the proxy instead:
`curl -so /dev/null -w '%{http_code}' https://<host>:<proxy-port>/api/projects`
answering 200 is the same finding. Remove that server block, or add
authentication to it, as well.

#### The static token leaked

`--token` / `CLOOP_UI_TOKEN` acts as an administrator outside RBAC and never
expires. Retire it first (no Secret edit and no restart needed), then work out
what it was used for:

```bash
# 1. Refuse it on every member, now. Running hubs refuse it within about a
#    second and close the dashboards and sandbox terminals it opened.
cloop hub token static retire --reason "leaked in a CI log, INC-4412"
#    On a hub with no single sign-on and no admin API token this is refused:
#    nobody could administer the hub afterwards. Mint one first, or add --force.
cloop hub token create break-glass --role admin --expires-in 7d

# 2. Is anyone still presenting it? Refusals are counted, with the last address.
cloop hub token static status

# 3. What did it do while it worked? Where a role policy is in force its
#    requests are recorded under the actor static-token; on a hub without one,
#    under local.
cloop audit-log list --actor static-token --since 72h
cloop audit-log list --type static_token.retired

# 4. Callers that still need a credential get a scoped API token — or, if a
#    static token is unavoidable, a new CLOOP_UI_TOKEN value and a restart.
```

The dashboard has the same action: Settings → Static admin token → Retire. The
token can retire itself, so an operator who holds nothing else can use it one
last time to lock it. A retired token stays configured (a token-only hub stays
closed and accepts only API tokens), and each refusal tells the caller when and
by whom it was retired; the reason stays in the trail. A member started with
`ui.cluster.exclusive` reads no bus and refuses the token within 30 seconds.

#### A session was stolen

Contain the session first, then the credentials behind it. Revoking the session
first stops the active use while you work out what else the account holds.

```bash
# 1. See what the account has open, and from where. The IP column is usually
#    what tells a stolen cookie from the user's own second browser.
cloop hub session list --identity alice@example.com

# 2. End one session, or all of theirs.
cloop hub session revoke 3f9c1e7a2b5d48c0 --reason "reported stolen laptop, INC-4412"
cloop hub session revoke --identity alice@example.com --reason "credential compromise INC-4412"

# 3. Sessions are not the only credential. Revoke any API token the account holds.
#    A token listed "(unapproved)" was minted while no role policy was in force;
#    a hub enforcing one refuses it until `cloop hub token approve <id>`.
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

Running hubs were told: they stop honouring these sessions and close the
dashboards and sandbox terminals they opened within about a second. A hub
started with ui.cluster.exclusive reads no announcements: it stops honouring
them within 30s (its session cache) and closes their streams at the next
30s re-check after that.
API tokens are a separate credential — see `cloop hub token list`.
```

**Revocation reaches what the session already opened.** The command announces
each session it ended on the hub bus. Every hub reading the bus (every `cloop
ui` that joined the control plane, which is the default) drops the session from
its cache and closes the dashboard WebSockets, SSE streams and
[sandbox terminals](attach.md) it opened, within one bus poll. The person sees
"Your session was ended" and is sent back to sign in; their terminal into a
sandbox shows the same message and closes. The same applies to an `api_token` revoked with `cloop
hub token revoke`, and everything `cloop hub user offboard` ends. Revoking from
the Sessions or Tokens panel does the same without the bus round trip.

**Two delays remain.** A hub started with `ui.cluster.exclusive` reads no bus.
It serves the session from its 30-second cache, and closes the session's
streams at their next 30-second re-check after the cache drops the session, so
up to a minute in all. And if the command warns that it *could not notify
running hubs*, every hub is in that position. If you need either delay to be
zero, stop the hub.

This command reads and writes the session table directly and takes no
control-plane lease, because it is meant for a hub whose listener is stuck, and
that hub still holds its lease.

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

# 3. Stop what is already running. A daily budget applied to a live hub does
#    end the run, but only once the spend catches up with it; the others
#    (max_concurrent_tasks, max_projects) bound the next request and nothing else.
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

**This command refuses while a hub is running**, and points you to the REST
API:

```console
$ cloop hub quota set alice@example.com --limit daily_cost_usd=5 --reason "runaway plan"
Error: a hub is running here and holds the control-plane lease: hub-1 (cloop-0 pid 812)

This command writes state that hub loaded into memory at startup, so a
write now would neither take effect nor survive its next edit. Use PUT
/api/quotas/{identity} or the Quotas panel while it is running, or stop it first.
```

The enforcer reads overrides once at startup, so a write behind a running hub's
back would be ignored *and* overwritten by the next edit made in the panel. Use
the Quotas panel, or:

```bash
curl -X PUT https://hub.example.com/api/quotas/alice@example.com \
  -H "Authorization: Bearer $CLOOP_PAT" \
  -H 'Content-Type: application/json' \
  -d '{"limits":{"daily_cost_usd":5,"max_concurrent_tasks":2}}'
```

A `daily_cost_usd` or `daily_token_budget` set this way does stop the run that
caused it. The hub adds each project's cost rows to the enforcer every 30
seconds, so the run ends at the first task boundary after the budget runs out,
with `quota.spend_refused` in the audit trail naming the identity, the limit
and the usage. The other ceilings only limit the next request.

`cloop hub quota list` shows *how much* an identity is over. To see *where it
went*, use `GET /api/cost/identities?window=today` across the fleet, or
`cloop cost report --by-identity` inside one project. See
[per-identity attribution](../security/model.md#who-spent-it-per-identity-attribution).

#### Somebody leaves

**One command.** Disabling an account at the identity provider doesn't, by
itself, end anything this hub has already issued. Seven things survive it:

| Surface | What survives an IdP disablement |
| --- | --- |
| Sessions | Until the absolute TTL. The refresh grant proves the grant is alive, not that the person still works here. |
| API tokens | Until `ExpiresAt`. The owner binding isn't checked when someone leaves. |
| Glasses links | The same rows and the same problem, for up to 30 days |
| Deny binding | Doesn't exist until somebody writes it |
| Secret leases | Real credentials, materialised inside a running sandbox |
| Running tasks | Still executing, in their name |
| Project memberships | Other people's projects shared with them by name, until a maintainer removes them |

Four more are things they have stored here:

| Stored | What survives an IdP disablement |
| --- | --- |
| Personal secrets | Their GitHub PATs (including the git-proxy-guarded ones) and kubeconfigs, sealed, indefinitely |
| Grants over them | Live, including grants to projects other people own, which keep using the departed person's credential |
| Grant requests | Still pending; an approver could mint a grant for somebody the hub no longer admits |
| Claude Code login | Their OAuth refresh token in plaintext, the CLI's transcripts and project history, under every hub member's config directory, and any login they had in progress, in a member's memory |

`cloop hub user offboard` ends all seven, destroys all four, and reports one
more thing, the projects they own, without touching them.

**With SCIM provisioning, the identity provider ends access itself**
([guide](../guides/scim-provisioning.md)). Disabling, deleting or unassigning
the person there suspends them here at the provider's next cycle: the deny
binding, sessions, API tokens and glasses links in one transaction, then their
leases and running tasks, and every grant over their personal secrets is
suspended. That covers the first six of the seven without anyone running
anything. A suspension keeps their memberships and stored credentials, because
a disabled account is often only disabled for a while. The provider's
`DELETE`, or `ui.oidc.scim.offboard_after_days` of deactivation, runs this
command's full offboarding as `scim:<credential>`. So with provisioning, run
the command by hand to cover the minutes before the provider's next cycle
(about 40 on Entra; or use its *Provision on demand*), or to finish what a
suspension keeps without waiting. `cloop hub audit --entity-type scim_user`
shows what the provider did.

```bash
# 1. Look first. Nothing is changed, and the set printed is exactly the set
#    the write acts on.
cloop hub user offboard alice@example.com --dry-run

# 2. Do it.
cloop hub user offboard alice@example.com --reason "left the company, HR-882"

# Under a legal hold: sever access, keep what they stored.
cloop hub user offboard alice@example.com --keep-credentials --reason "left, legal hold LH-17"
```

Sessions, API tokens, glasses links, project memberships and the deny binding
are written in **one transaction**: either the person is removed from all five
or nothing changes, so you never find a half-offboarded account a month later.
Leases, the stored credentials, running tasks and Claude Code logins can't be
part of that transaction (they live in broker memory, other databases and other
hub members' filesystems), so they are handled after it, in that order. Any
failure there is reported, not rolled back, because the transaction has already
ended the person's access. A partial run exits non-zero.

**What they stored is destroyed after that**, and each step reports its own
failure:

1. every live grant over their personal secrets is revoked; the dry run lists
   each one with its subject, so you can see a shared project that is about to
   lose a colleague's credential before you confirm;
2. their personal secrets are deleted through the broker: the sealed payload
   and wrapped data key are overwritten before the row is deleted, the
   write-ahead log is checkpointed so the database file itself holds zeroes (a
   checkpoint that a reader held off is a warning), the deletion is audited,
   and a tombstone keeps the name;
3. their pending grant requests are withdrawn; your reason goes on the audit
   row, not in the note that request reviewers see;
4. their running tasks are told to stop, as before;
5. their Claude Code login ends on every hub member: a login in progress is
   cancelled, each home is logged out with `claude auth logout`, which revokes
   the session at Anthropic, and its directory is removed.

None of this needs `CLOOP_SECRET_KEY`: destroying a credential removes rows
without reading them, so the command works from a shell without the hub's
sealing passphrase. On a hub with `executors.allow_host_process: false`, the
dashboard's offboarding skips the logout, because that hub runs no program on
behalf of a request, and the report says the credential was destroyed on the
hub but not revoked upstream. The CLI, running in an operator's shell, logs out
the homes in its own tree whatever the policy, and members handle their own. A
task stop is asynchronous: if one of their runs on the hub's host was still
finishing, run the offboarding again once it has stopped, so that nothing it
wrote into a removed directory survives.

**Every member's Claude home.** A home lives under the config directory of the
process that created it, not in the database. The command removes the copy
under its own directory and asks every running hub member over the bus to
remove theirs; the dashboard asks the other members over the peer channel. A
copy that couldn't be reached is reported as a failure that names it, but you
don't have to clean it up by hand. Every hub member also removes from its own
tree the Claude home of every identity the control plane denies hub-wide, at
startup and every hour after, logging it out first where it is allowed to and
recording each as `user.claude_home_swept`. A legal hold keeps the homes
(`--keep-credentials` records a hold on the identity before anything is denied;
release it with `cloop hub user hold release`), and so does a SCIM suspension
that is still in force, which a reactivation undoes. `cloop hub doctor` fails
`offboard.claude_homes` while a home that a sweep would remove is still on its
host, naming each directory:

| Failure says | What to do |
| --- | --- |
| `hub member … did not answer … a build older than this one` | Nothing, once it runs this build or later: it removes the copy at its next sweep, within the hour, or as it restarts. On an older build, upgrade it, or remove the listed `claude-identities/<slug>` directories under its config directory by hand |
| `… holds this control plane exclusively (ui.cluster.exclusive)` | That hub reads no bus, but sweeps its own tree like any member, within the hour. Offboard from its dashboard to remove them now |
| `… stopped … kept Claude logins under … on <host>` | A stopped member left its tree on a host that is still up. It removes them itself when it starts again; if it never will, remove the named directories there (`cloop hub doctor` on that host names them) |
| `refused to end the Claude logins of …` | A member found no deny binding for that spelling; check `cloop hub role list --identity …` |

Running it again is safe: anything already destroyed isn't found again.

**A colleague's project that loses a credential is told.** If one of the
person's personal secrets was granted to a project somebody else runs, that
project's next run is refused the secret by name
(`github_pat "alice-pat", a personal credential of alice@example.com, was destroyed on 2026-10-10 when its owner was offboarded`),
in the lease's audit row and, once per hub process, as a `credential_refused`
event on the project's own Activity tab. Under a legal hold it reads "was
withdrawn … when its owner was offboarded", and it still names the credential
when the secret is destroyed days later. Your offboarding reason is never
included, and the dashboards that refresh their Secrets panel aren't told whom
it concerns. The project needs a credential owned by somebody who is still
here. A lease the project's run already holds isn't taken away mid-run. Its
revoked grant stops the lease from being extended, so it lapses within 15
minutes, and the dry run names it with the time. Revoke the lease under
**Secrets → Leases** to end it sooner.

**A legal hold** (`--keep-credentials`, or *Legal hold* in the dashboard) keeps
their personal secrets and Claude Code homes as they are. You can also place a
hold *before* anyone offboards
(`cloop hub user hold place alice@example.com --reason "LH-17"`), and then
every offboarding of that identity honours it, including those the identity
provider triggers through SCIM, where nobody is at a prompt to pass
`--keep-credentials`. `cloop hub user
hold list` shows the holds in force; `release` lifts one and destroys nothing
by itself. Access is still ended: the grants are revoked, the requests
withdrawn and any login in progress cancelled. A hold preserves evidence; it
doesn't keep a departed person's credential in use. The report lists what was
kept, and `user.offboard_hold` records that the hold was in force. When the
hold is lifted, run the offboarding again without `--keep-credentials`: it
finds what was kept and destroys it. The person's sessions are gone by then,
and a session is one of the things that link an email to a subject, so give
each spelling the first report resolved to (the email, then `sub:<subject>`).
Alternatively, delete the kept secrets from the Secrets panel (admins may
delete another person's personal secret) and remove the homes with the slug
recipe in
[per-user Claude Code logins](../security/claude-code-identity.md#deprovisioning-a-user).

**Give an email or a subject; either resolves to both.** The surfaces are keyed
inconsistently (a session carries an email, but a token's owner may carry only
a subject), so the command expands what you type to every identifier that
turns out to belong to the same person. Matching only the literal input would
leave a departed user's PAT working.

**Projects are reported, never deleted.** They usually hold the team's work.
The command lists them and writes a `user.offboard_project` audit event so that
the reassignment is on record; use `cloop workspace` to hand them over.

The trail has one event per surface touched, all under entity type `user` and
keyed by the identity, so one query finds the whole operation:

```bash
cloop hub audit --entity-type user --entity-id alice@example.com
```

The same operation is in the dashboard under **Secrets → Offboard a user**, and
requires `user.manage`. Like the CLI, it shows a preview before it writes, and
its *Legal hold* box is `--keep-credentials`. It refuses to offboard the
identity making the request, because that would revoke the session making the
request and deny the account that would have to undo it. Use the CLI if that is
really what you want.

> Running hubs are told about every session, token and glasses link this ends,
> and within about a second they close the dashboards and sandbox terminals
> those opened. A hub started with `ui.cluster.exclusive` reads no
> announcements: it may accept a revoked session for up to 30 seconds (its
> session cache), and closes what the session opened at the next 30-second
> re-check. Deny bindings take effect within ten seconds.

#### An admin is compromised

Admin status comes from `oidc.admin_emails` and `oidc.role_mappings`, which are
read at startup, so changing them means editing the configuration and
redeploying, with whoever controls the deployment pipeline involved.

Instead, `cloop hub role revoke` writes a **deny binding** into the
control-plane database. It takes precedence over every other binding at every
specificity, including the global admin binding that `oidc.admin_emails`
produces, and a running hub picks it up within ten seconds without a restart.

```bash
# 1. Confirm where their authority comes from. This shows both layers: the
#    runtime bindings and the configured ones they override.
cloop hub role list --identity alice@example.com

# 2. Demote. This works while the hub is running.
cloop hub role revoke email alice@example.com --reason "credential compromise INC-4412"

# 3. A deny stops them acting. It does not end sessions or revoke tokens.
#    `cloop hub user offboard` does all three in one transaction, and is the
#    right tool unless you specifically want to demote without ending sessions
#    (e.g. containing an account you are still watching).
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

**How long containment takes.** There are three delays, which add up in the
worst case:

| | Bound | Why |
|---|---|---|
| REST and page loads | 10s | the binding TTL: bindings are re-read from the database at that interval |
| Open WebSocket or SSE stream | +30s | the writer loop re-checks the deny on its keepalive tick and closes the connection |
| Revoked session | ~1s | announced on the hub bus, which drops it from every member's cache and closes the streams and terminals it opened; 30s for a request and up to 60s for a stream on a `ui.cluster.exclusive` hub, which reads no bus |

So a demoted account can no longer *act* after about ten seconds and stops
*receiving* after about forty, or after about a second once step 3 has revoked
its sessions and tokens, which closes every stream and sandbox terminal they
opened. If you need both delays to be zero, stop the hub, which is also what
you would do if you suspected the process itself.

**Precedence.** Two rules decide it, and nothing else:

1. **Deny wins.** An applicable deny binding denies outright, whatever else
   matches and at whatever specificity.
2. **The database overrides config.** If any runtime binding applies, the
   configured bindings are not consulted at all.

Step 2 above needs both. If a deny were ranked against a tier-0 admin binding,
it would lose; if the configuration were consulted after a runtime match, the
admin binding would come back.

**Scoping a deny.** With neither flag the deny is global. With `--project` it
removes authority on one project and leaves the rest as they are:

```bash
cloop hub role revoke email contractor@example.com --project payments --reason "scope reduction"
```

**Other claims work too**, which matters when the provider releases no email:

```bash
cloop hub role revoke sub 8f14e45fce      --reason "offboarded, IdP entry not yet removed"
cloop hub role revoke group contractors   --reason "vendor breach, containing the whole group"
```

`cloop hub role grant` works the same way in the other direction. A runtime
grant overrides the configured bindings, so you can also use it to narrow
somebody's access (`--role viewer`) or widen it for one project, without a
redeploy. It doesn't override a deny, and it doesn't undo one: granting over a
live deny stores a row that has no effect. The command says so. Use
`role delete` to undo a deny.

A binding can't be limited to a project and an executor at the same time. No
request carries both (an executor action is a fleet action and resolves with no
project), so such a binding would match nothing. The command refuses it instead
of storing a deny that removes nothing.

Runtime bindings are policy that no reviewed file records, so a hub that has
any reports them at startup. A hub with single sign-on and no role policy
prints `RBAC: off` there instead and warns on stderr; its runtime denies still
apply, and are counted on the same line. Otherwise the line looks like this:

```
RBAC: 2 role mapping(s), default role "none", plus 1 runtime binding(s) (1 deny) — see `cloop hub role list`
```

Treat that line as a reminder to clean up: a deny left over from a closed
incident is an account that somebody thinks still works.

---

**A credential leaked.**
`cloop secret revoke <grant-id>` takes the grant back from every running
workload holding it and prints what each hub member took back; read the
output. A member that didn't answer, a device that was unreachable, or a
variable already in a running process's environment (a host process or a
device's task keeps its copy until it exits) means the credential may still be
in use. Stop those runs, or revoke their lease with `action=kill` from the
Secrets panel. Rotate the credential at its source.
`cloop audit-log list --entity secret --since 7d` shows who granted what and
when. For egress, `cloop egress revoke` takes effect immediately: live sessions
are torn down mid-tunnel. That happens at once when you revoke in the dashboard
of the hub holding them, and within a minute when you revoke from the CLI or
another hub member, because the holding hub re-reads the grant every minute
during a run.

**An executor is compromised.**
Run `cloop executor revoke <agent-id>` (it cascades to the credential, and the
agent is told not to reconnect), then `cloop executor cordon` any peer that
shared its grants. Read what both print. The revocation names the hub member
that held the agent's connection, the leases it scrubbed off the device before
dropping it, and any still pending; a cordon names the leases it took back from
the peer. An agent that was offline is refused when it next connects, but
whatever its device already holds stays there. Check the audit log with
`--entity executor` for what it was given. Assume every secret ever leased to
it is disclosed, and rotate accordingly.

**`cloop audit-log verify` exits 2.**
Don't vacuum or run maintenance, because both rewrite pages. Snapshot the file,
run `cloop db verify` to tell corruption from tampering, and compare with what
your audit sinks received (`cloop hub audit forward verify` on their copy) to
find where the histories diverge.

**`cloop hub audit verify` exits 3.**
The chains are intact and record events that could not be appended.
`cloop hub audit list --type audit.gap` shows, for each gap, how many events
were lost, of which actions, when, and why (`reasons`: `full`, `readonly`,
`locked`, …). Fix the cause (usually a full disk, so free space first), and
treat the listed actions as the part of that window the trail can't account
for. Then use `--allow-gaps` in the scheduled check until the next gap.

**`--checkpoints` names a truncated tail or a restored backup.**
Stop the hub before anything else writes, snapshot `state.db`, and keep the
checkpoint file and its off-machine copies as they are. A planned restore
explains itself, so check for backups taken or restored around the time the
finding names. A restore nobody ran, or a truncation, is an incident. Recover
the rows after the last checkpoint the chain agrees with from your audit sinks'
copy (the forwarder sent them as they were written), and investigate the window
in which they disappeared. The hub's next forward records an
`audit.forward.discontinuity` row naming the cursor it lost.

**`/readyz` fails but `/healthz` passes.**
Read the `check` field first; it names the gate that failed.

`"check": "sqlite"` is storage. Check that the volume is mounted and writable,
then run `cloop db verify`. Under Kubernetes, check that the PVC is bound and
that every replica runs on the node the volume is attached to: SQLite's
write-ahead log needs every process using it on one kernel, so the chart pins
replicas to that node and refuses to render more than one without persistence
(`replicaCount` defaults to 1).

`"check": "identity"` means the hub has never resolved its OIDC issuer, so
nobody can sign in. The `error` field names the URL that was contacted and the
HTTP status it returned, and `remediation` says what to change. For the full
diagnosis, run `cloop hub doctor` on the same host. It makes the same two
requests and prints the resolved authorization, token and JWKS endpoints,
which is the quickest way to tell a wrong realm path from a certificate the hub
doesn't trust. The gate clears by itself once the provider answers, including
through an ordinary sign-in; no restart is needed.

`"check": "executors"` means the hub has nothing to dispatch to: strict mode is
on and no isolating executor is registered. The `remediation` field says what
to do. The usual causes, most frequent first:

- the configuration enables no isolating backend at all: set
  `executors.container.enabled` or `executors.kubernetes.enabled`, or enroll an
  edge device;
- one is enabled but could not be *built*: no container runtime on the hub
  host, or no kubeconfig grant. `GET /api/executors` has a `reconciliation`
  block with a per-driver `status` and `remediation`, and the startup log has
  the same line;
- the hub is running in a distroless image (as the chart's is) with
  `executors.container.enabled: true`. There is no container runtime inside
  that image; use the Kubernetes backend, which is what
  `executor.kubernetes.enabled` in `values.yaml` configures.

Do **not** set `allow_host_process: true` to clear this. It makes the probe
pass by removing the isolation boundary the gate exists to enforce.

**Users keep seeing "Your sign-in needs renewing".**
The dashboard tried to re-check their claims from the browser, because the hub
holds no refresh token for the session, and the provider wouldn't answer
without showing the user something. Clicking **Sign in** fixes it for one
`max_claim_age_minutes` window. If it happens to many users,
`cloop_oidc_renewal_total{outcome="interaction_required"}` will be rising.
Either their browsers keep the provider's cookies out of frames (Safari,
Firefox, a hardened Chrome), or the provider refuses to be framed at all; the
latter never reaches the hub and shows only in the browser console as a framing
violation. The fix is the same in both cases: set `CLOOP_SECRET_KEY` and add
`offline_access` to `ui.oidc.scopes`, so the hub re-checks the claims itself
and the browser never has to. In `cloop hub session list`, a session that stays
at `never` under IDP CHECKED is one the hub has nothing to re-check with. See
[Silent renewal from the browser](../security/model.md#silent-renewal-from-the-browser).

**The hub exits with "another cloop hub controls this state and cannot share it".**
A hub that isn't a cluster member is serving this control plane: one from
before clustering, or one running with `ui.cluster.exclusive`. The new hub
refused to start so that the two don't diverge. See
[when a hub refuses to start](#when-a-hub-refuses-to-start).

**A member logs "stepped down: leadership was lost".**
It couldn't renew the lease for a full TTL, usually because of a long pause (a
suspended node, a stalled volume), and another member took over the leader's
duties. It keeps serving as a member: only the duties moved, not the
dashboard. If this happens repeatedly, look for what is stalling that process.

**A hub started with `ui.cluster.exclusive` logs "standing down" and exits.**
This is the same loss of the lease, under the pre-cluster rule that setting
restores: another hub now owns the state, so this one stops instead of serving
alongside it. Find the other hub with `cloop hub lease status`.

**A sandbox cannot reach something it should.**
Work through the layers; each step rules one out.

1. **Ask the filter.** `--check` reports the verdict and the rule that decided
   it, and puts the verdict in the exit status (0 allow, 1 drop), so you can
   use it in a script. Give it the *address*, not a hostname, because a packet
   filter matches addresses:

   ```console
   $ cloop egress firewall --cidrs 10.8.0.0/24 --ports 6443 --check 10.8.0.5:22
   DROP  10.8.0.5 10.8.0.5:22/tcp — private (RFC1918/ULA)
   ```

   Read the reason. `private (RFC1918/ULA)` means the address was inside the
   granted range but the *port* was not, so the exception didn't apply and the
   block set caught it. `default deny` means nothing matched at all. Use the
   same flags the executor is configured with, or `--grant <id>` to compile a
   stored grant. See
   [`cloop egress firewall`](../reference/commands.md#cloop-egress-firewall).

2. **Check that DNS is allowed. This is by far the most common cause.** A
   `filtered` policy with no `resolvers` drops UDP/53 along with everything
   else it doesn't name. The symptom isn't "DNS is denied": every connection
   fails at name resolution, which looks like a network outage. The compiler
   warns about this:

   ```console
   $ cloop egress firewall --internet --ports 443 --format rules | grep -m1 resolver
   warning: no resolver is allowed, so DNS will fail: name lookups leave the sandbox on UDP/53 and this policy drops them. Pass the sandbox's resolvers, or use the broker, which resolves on its behalf.
   ```

   To fix it, name the sandbox's resolvers in
   `executors.container.egress_filter.resolvers`, or route the sandbox through
   the broker, which resolves names on its behalf. On Kubernetes, check that
   `allow_cluster_dns` hasn't been set to `false`. Resolvers are opened on TCP
   as well as UDP, because a truncated answer is retried over TCP, and a
   UDP-only resolver fails on large responses in a way that looks like a
   different bug.

3. **Look at the counters on the host.** Every rule has one, so the ruleset
   shows what is actually being dropped:

   ```bash
   nft list table inet cloop_sbx_<executor-id>
   ```

   The table name is `cloop_sbx_` plus the executor id in lower case, with
   every character outside `[a-z0-9]` replaced by `_`. A non-zero counter on a
   `drop` rule names the destination range and the reason. A zero counter on
   the `default deny` line means the traffic never arrived, which points
   upstream: at routing, at the image, or at a workload that never tried.

   There is **no table for an `internal: true` filter**, and that is expected:
   that form installs no rules at all, because the runtime gives the bridge no
   route out in the first place. If `nft list table` says the table doesn't
   exist, check which form the executor is configured with before concluding
   that the filter failed to install. A failed install fails the `Start`, so a
   running sandbox never has missing rules.

4. **Run preflight again.** `cloop executor test <executor-id>` reports the
   driver's `egress` finding (what the filter will enforce, or that it isn't
   filtering at all), plus a separate `egress-scope` finding for anything where
   the filter is wider than its grant. Exit 2 means preflight found a fatal
   problem and didn't try a workload. The usual problems are `nft(8)` missing
   or the control plane lacking `CAP_NET_ADMIN`. Both are `fail`, both have the
   fix in the message, and you can avoid both by switching the filter to
   `internal: true`, which needs neither. `cloop hub doctor` doesn't repeat
   these findings: its `executors` group reports reconciliation, the
   strict-mode gate and a liveness probe.

5. **On Kubernetes, confirm that the CNI implements NetworkPolicy.** cloop
   creates the object, and the API server stores it whether or not anything
   enforces it, so from the hub's side a cluster running flannel looks the same
   as one that works. There the failure is the opposite of this playbook's:
   traffic that should be *blocked* is not. `kubectl get netpol -n <ns> -o yaml`
   shows what was created; only the CNI's own documentation says whether it is
   enforced.

If the sandbox should reach the destination through the **proxy** and not
directly, use `cloop egress test <url>` instead. It asks the layer-7 question,
and a host allowlist is only enforced there.

**A run's requests through the egress proxy fail.**
First read the project's Event History for `egress` rows. Every run whose
project holds a grant gets either a "proxy session … issued … reaches the proxy
at X" row or a row saying why it got none: the grant was revoked or expired,
there is no proxy on the hub, the run has no network, or there is no route from
its executor (a loopback-bound proxy and a container, an advertised address a
device can't reach, an agent older than v18 behind a device firewall).
`cloop hub doctor` reports where each running hub's proxy listens
(`egress.hosted`). The audit trail has the rest: `egress.redeem`, one
`egress.connect` / `egress.request` per verdict with the host, port and reason,
`egress.renew`, and `egress.close` with the session's byte counts. A harness
that honours `HTTPS_PROXY` sends its model API traffic through the proxy too,
so when a harness can't reach its model, the usual cause is a grant that
doesn't include the model API's host.

**"database is locked".**
WAL and `busy_timeout` are already configured, so this points to a second
writer. Check for a stray `cloop` process on the same `.cloop` directory, or a
shared volume.

**A run stopped: "run progress could not be saved".**
The project database refused a write the run needed (a task's outcome, a pause,
a plan change), so the run stopped instead of reporting work the database
doesn't hold. The badge, `cloop status` and the Event History name the write
that failed and the database's own error:

```
Status:   paused
Reason:   could not save task #12's completion (status done): database or disk is full
```

The usual causes are a full disk, a read-only mount or file permissions, a
lock another process held past `busy_timeout`, and a damaged task row (see "A
task row that will not load" above). Fix the cause first; `cloop db verify`
checks the file itself. Then start the run again. The tasks the stopped run left
in progress are recovered the usual way: an outcome its agent had already
reported is adopted instead of being run again, and anything else is re-queued.

When the database accepted nothing at all, not even the stop, the run exits
with status 74 and its last lines of output say what failed. The hub reads that
status, records the same pause on the run's behalf, and journals it, so the
dashboard shows the same either way, as long as the hub itself can write.

**Nothing will schedule.**
Read the placement error: it names the constraint and lists the reason each
candidate was rejected. `host_policy` means strict mode refused the only
available executor: the policy is working, and the fleet needs changing. Bind
the project to an isolated executor or enable the container backend. Do **not**
set `allow_host_process: true` to make the message go away.

**A project shows "running" but nothing is running.**
This resolves itself. A run that is killed instead of stopped (by the kernel's
OOM killer, a `SIGKILL`, a host reboot) never writes a terminal status, and the
hub reconciles that within a few seconds. The project returns to `paused`, each
task the run left in progress is either adopted (its agent had finished and
said so, so the outcome is used and the work isn't redone) or re-queued, and
the event journal records why. Look there first: the entry names the cause, and
an out-of-memory kill is reported as such, with the fix (give the executor more
memory, or make the task use less at once). Repeated OOM entries for the same
project are a sizing problem, not a cloop problem.

If it does *not* resolve, the hub refused to repair it. Check the server log for
`stale-run recovery: skipped, state points at another directory`. That is a
project whose `.cloop` was copied or moved from somewhere else, so its stored
`WorkDir` names its old location, and the repair would be written to the
original project's database. Fix the state file.

**Restarting the hub does not stop the runs it started.**
This is intended, and it is why the nightly rebuild of `cloop-latest` doesn't
interrupt work in progress. Runs are orphaned, not killed (`KillMode=process`
on both hub units), and are designed to outlive the hub: a run whose output
pipe breaks keeps working and still records its outcome, so losing the hub
costs only the live-log stream. Progress keeps being written to `state.db`, so
the task list stays current even while the log panel is empty; streaming
resumes with the *next* run, not the one that was in progress. A run on an edge
device fares better: the restarted hub adopts it when its agent reconnects, and
streams, merges and settles it as the stopped hub would have. See
[after a control-plane restart](#after-a-control-plane-restart).

In older builds such a run died, not from the kill but at its own next log
line, because Go makes `SIGPIPE` fatal on file descriptors 1 and 2. The work
was committed but the outcome was lost, which was the most common reason for a
project to get stuck showing "running". To stop a run, use the Stop button or
`POST /api/projects/{idx}/stop`.

---

## See also

- [Executor architecture](../architecture/executors.md): health, cordon, failover
- [Security model](../security/model.md): what the boundaries authenticate with
- [Threat model](../security/threat-model.md): deployment-level threats
- [Secret and egress grants](../guides/secrets.md): grant and revoke procedures
- [Kata Containers](../guides/kata.md): VM-isolated sandboxes, setup and verification
- `deploy/README.md`: image, compose stack and Helm chart specifics
