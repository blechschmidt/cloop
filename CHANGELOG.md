# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

While the major version is 0, the command-line surface, the configuration
schema and the hub's HTTP API may change in any release.

## [Unreleased]

### Security

- **Sudo mode: on a hub with single sign-on, privileged actions need a recent
  interactive sign-in, not just a live session cookie.** A session carried its
  owner's full authority for its whole absolute lifetime (24 h by default), and
  silent renewal kept it alive without the person ever authenticating again,
  so a cookie lifted from a laptop could mint API tokens, grant secrets and
  rewrite role mappings for up to a day. Now creating or deleting a secret or a
  grant, approving a grant request or an API token, minting an API token or an
  executor enrollment token, editing `ui.oidc` (role mappings, `require_rbac`),
  retiring the static token, rotating the hub CA, upgrading or deregistering an
  executor, attaching to a sandbox, granting project membership at maintainer,
  ending someone else's session, offboarding, minting a SCIM credential or a
  glasses link, and setting a provider's API key or base URL, the dictation key
  or the CI relay's settings ask for a sign-in within
  `ui.oidc.sudo_max_age_minutes` (default 120, 1–1440, `-1` off). It is measured from the ID token's `auth_time`, or — where the
  provider reports none, as Entra ID does unless that optional claim is
  configured — from a sign-in the hub started with `prompt=login`; silent
  renewal never counts, and the time is stored on the session row (migration
  0083, additive) so every hub member agrees. A stale session gets
  `401 REAUTH_REQUIRED`, which the dashboard turns into a "Confirm it's you"
  dialog that signs in again at the provider (`prompt=login&max_age=0`) in a
  window of its own and then replays the action. A terminal session counts from
  the sign-in behind its `cloop login` approval — approving from a browser whose
  sign-in is not recent is itself a `prompt=login` sign-in — and a stale one is
  told to run `cloop login` again. API
  tokens and the static token are not sessions and are not asked. The route
  table declares the rule beside each permission and a test fails a privileged
  route that neither asks nor is exempted with a reason. Refusals and
  confirmations are audited as `session.reauth` and counted in
  `cloop_session_reauth_total{outcome}`; `cloop hub doctor` and Hub health warn
  (`oidc.sudo`) when it is off. **On :8888 (Entra ID, no `auth_time`) admin
  actions will ask for a fresh sign-in after the next deploy** — the first one
  in each two hours. To turn that off, set `sudo_max_age_minutes: -1` under
  `ui.oidc` in that hub's `.cloop/config.ui-8081.yaml` (or in Settings →
  Single sign-on) and restart it (Task 20448).
- **Copilot on a hub with single sign-on acts for the person: no run on the
  hub's host, dashboard model call or resume spends the hub's own Copilot
  sign-in any more.** The `copilot` provider passed the hub's environment to
  the CLI, which signs in with `COPILOT_GITHUB_TOKEN`, `GH_TOKEN`,
  `GITHUB_TOKEN`, then the hub user's `copilot login` — so every person's run
  on the hub's host, every Split, Revise, blocker analysis, plan-assistant
  call and replay on a copilot project, and every auto-resume and failover ran
  on one person's seat or on a token the service held for something else, a
  person with no credential was served on it, and everybody's conversations
  went into one `~/.copilot`. Now such a dispatch needs a Copilot credential
  granted to the project that counts for its person — their own token, pasted
  into the *Copilot credential* card and kept as their personal secret
  (`github_pat_`, `gho_`, `ghu_`; never `ghp_`, `ghs_`, `ghr_`), or one shared
  with the project — and is refused with the `409 harness_credential_missing`
  that opens the dialog otherwise; a resume or failover acts for the recorded
  starter and holds the run `starter_unavailable` without one. Every harness
  dispatch to the hub's host — whatever its provider, as a review gate's
  reviewer may be Copilot — has the hub's own Copilot variables blanked before
  the lease and the person's own Copilot home (inside their identity home, so
  offboarding and the denied identities' sweep remove it) pinned after it, and
  the provider strips every `COPILOT_*`, `GH_TOKEN`, `GITHUB_TOKEN` and
  `GH_HOST` the CLI would inherit but that credential. A deactivation at the identity provider suspends the
  credential with the person's other personal ones; offboarding and a deletion
  destroy it. `tests/arch` and the `tests/security` call graph now hold every
  lease and every in-hub path to the pin. Single-user hubs are unchanged
  (Task 20449).
- **cloop's published images are signed, and a hub verifies cloop's own image
  by digest before a sandbox runs it.** `publish-images.yml` pushed
  `ghcr.io/blechschmidt/cloop`, `cloop-harness` and `cloop-harness-copilot`
  unsigned, and the image every sandbox runs by default — the mutable tag
  `cloop-harness:latest` — was exempt from `sandbox.image_policy` along with
  every image an operator chose, so anyone who could push to those packages (a
  leaked publishing token, a compromised workflow) decided what ran beside every
  lease's credentials on every hub using the default. Now the workflow signs
  every digest it pushes, keyless — the multi-arch index and each platform
  manifest — verifies them against its own identity, and proves the negative: a
  digest nobody signed, and the release and edge pins, are refused, including
  by the published hub's own `cloop hub verify-image` with the cosign it now
  bundles. `pkg/provenance` gains a third pin, `ImagesIdentityRegexp`, for that
  workflow on `main` and release tags only, overridable on its own with
  `CLOOP_PROVENANCE_IMAGES_ISSUER` / `CLOOP_PROVENANCE_IMAGES_IDENTITY`, and a
  drift test holds the workflow's triggers, pin and cosign version to it.
  Wherever the hub dispatches one of cloop's own images — the default, one
  configured explicitly, a device's or a virtual executor's sandbox image, one a
  project names — it resolves the digest (from the local store on the container
  executor, at the registry for a device), verifies it with cosign and
  dispatches the digest; Kubernetes can check only an image configured by
  digest and warns on a tag. The verdict and the verified digest are recorded on
  the handle, every task artifact (`sandbox_image_provenance`,
  `sandbox_image_verified_digest`) and the `task.dispatch` audit row
  (`image_provenance`, `verified_digest`). A signature present and wrong always
  refuses the dispatch. An unsigned image — every one published before this —
  or a hub without cosign is a warning on the run and in `cloop hub doctor` and
  Settings → Hub health (`images.provenance`, which also reports cosign's
  version), so an upgrade never stops a working hub; the new
  `executors.image_provenance: required` refuses them. The hub image bundles
  cosign v3.1.4, pinned by checksum. The new
  `sandbox.image_policy.govern_operator_images: true` applies the project rules
  to operator-chosen images that are not cloop's own. A device holding an
  older copy of a cloop image refuses a dispatch of the verified digest until it
  pulls it (`docker pull` of the digest the refusal names) (Task 20453).

### Added

- **Copilot projects run in sandboxes: a published image carries the GitHub
  Copilot CLI, and a device installs it on request.** A `copilot` project could
  not run on the flagship isolation path: the published harness image had only
  Claude Code, so in a container it failed inside the sandbox after its lease
  was issued, and a device without the CLI refused every dispatch until someone
  installed it by hand.
  - `ghcr.io/blechschmidt/cloop-harness-copilot` is the harness image with the
    CLI added, for `linux/amd64` and `linux/arm64`. It is a variant because the
    CLI is a 199 MB binary that unpacks a 247 MB runtime: measured on amd64 it
    adds 445 MB unpacked and 217 MB compressed (+65%, +81%) to the 685 MB /
    268 MB default image, which keeps carrying `claude` only. The CLI is pinned
    by version and by the sha512 integrity of every npm tarball the install
    unpacks, installed offline from those tarballs only, and checked with
    `copilot --version` at build (`scripts/copilot-cli-pins.sh` prints the pins
    for a newer one). Its runtime is unpacked at build time, read-only
    (`COPILOT_PKG_CACHE_HOME`), so a start writes nothing to the sandbox's
    512 MB in-memory `/tmp`; `COPILOT_HOME` is on that tmpfs for any uid, and
    `COPILOT_AUTO_UPDATE` is `false`.
  - Images say what they carry in an `org.cloop.harnesses` label
    (`claude,copilot,cloop,git`). The container executor — the hub's, or a
    device's in container mode or through a virtual executor — reads it in the
    inspect it runs before every start, and under `require_signature` the hub
    reads it for the digest it resolved at the registry. A project whose
    harness the label lacks is refused before anything runs, `409
    sandbox_image_lacks_harness`, naming an image that carries it; an image
    without the label is never refused.
  - A device installs `copilot` on request from GitHub's documented installer,
    `https://gh.io/copilot-install`, as it does `claude`, unless
    `executors.auto_install_harness` is off. `gh.io` redirects onto
    `raw.githubusercontent.com`, which serves every repository on GitHub, so
    the installer table now pins a path as well as a domain and accepts the
    script only from `github/copilot-cli`. Proved on sgx with
    `scripts/e2e/copilot-device`, and in CI by a copilot task run end to end
    in the image the commit builds, against a bring-your-own-key stand-in
    model (Task 20450).

- **Every push to main rehearses a rolling upgrade from the latest published
  release, and no release is published while the rehearsal is red.**
  `tests/upgrade` fetches the latest release's linux-amd64 archive, verifies it
  against cloop's release identity with cosign before any of it runs (cached by
  tag, verified on every use; without the network it skips, naming the host),
  and runs it beside the build under test on one database and one cluster: two
  release members with single sign-on, a release agent's device run holding a
  secret lease and git-proxy and Kubernetes-monitor sessions, CI exchanges and
  quota counters; then a member of the new build migrates, every column it
  added must survive the release members' writes, the release members are
  stopped one at a time, and the run must settle on the new build with its
  credentials, the audit chains and their checkpoints must verify, and the
  release's agent must be listed as an older build with an upgrade on offer.
  The rollback half holds the release to the runbook's Rollback section, word
  for word, for every verdict a migration can be recorded with. CI runs it as
  the *Upgrade rehearsal* job; the release workflow runs it from the release
  before against the binary it is about to publish and signs nothing while it
  fails; and the release procedure, now written down in CONTRIBUTING.md
  ("Cutting a release") and `pkg/version/releases.go`, requires it green on the
  commit being tagged. The runbook's example refusal now shows what `cloop ui`
  prints — `hubcluster: open <path>: statedb: …` since the hub cluster — beside
  what every other command prints (Task 20452).

### Fixed

- **A device's card lists a harness it installed on request without waiting
  for the agent to reconnect, and a device without the project's harness is a
  409, not a 500.** The Fleet panel read the device's hello, so after an
  install the card kept saying the harness was missing; and a dispatch the
  device refused for lack of a harness it was not allowed to install fell
  through to an internal server error (Task 20450).
- **A run adopted after a hub restart keeps a lease whose takeover failed for a
  moment, and tries again, instead of losing its credentials.** When the
  restarted hub — or the cluster member adopting a run — could not take a
  lease over because the secret store was unreadable for a moment, the
  database locked, the disk at its floor or a KMS down, it printed one line on
  stderr and moved on: the lease vanished from the run's owner row, nobody
  extended it, and the run's git-proxy and Kubernetes-monitor sessions and its
  App-token refresh went with it, so its next push or kubectl call failed with
  nothing on the run saying why. Now such a takeover stays on the owner row —
  a member adopting the run later sees it too — and the adopter retries it, two
  seconds later and then with the wait doubling to a minute, until it is
  decided or the lease's recorded expiry passes; a request presenting one of
  its sessions brings the next attempt forward. The same holds for the
  workspace lease and the egress session. The run's event history records a
  `lease_takeover` row when a takeover is first undecided and another when it
  is taken over or fails, with the reason; `cloop hub doctor` and Settings →
  Hub health warn `runs.lease_takeovers` while one is undecided; and
  `cloop_lease_takeovers_total{kind,outcome}` counts every attempt. A retry
  takes a credential only while its member still owns the run — the broker
  asks just before its conditional write — so it never takes back what a member
  that adopted the run since holds. A run that moves between two live members
  no longer has its egress session renewed by the old member for up to a day
  after the run ends: the old member ends it with the run, and the run's owner
  takes it over if the old member stops first. And the old member no longer
  settles a run it has just handed over: its output stream was cancelled before
  the run was marked handed over, so the stream's consumer could settle it
  here too — closing its egress session and recording it ended while the other
  member ran it. A Kubernetes Pod's workspace session still does not survive
  its hub process; that is now stated as a residual risk and pinned by a test
  (Task 20451).

- **A run that moves between hub members gives its tenant's concurrency slot
  back when it ends.** The member that dispatched a run gave the slot back only
  when its own stream of the run closed: a member stopped mid-run — every
  member, in a rolling update — exited first and never did, and the member that
  adopted the run did not know it held one, so every rolling update narrowed
  each tenant with a run in flight by one concurrent task until a member
  started alone and rebuilt the gauges; a tenant capped at one run could not
  start another. And a live member letting go of a run gave the slot back while
  the run went on elsewhere. The slot is now recorded on the run's owner row
  (`quota_slot`), given back once by whichever member settles the run, and
  never by a member the run left; the gauges a lone member rebuilds count a run
  for the identity that started it. A run dispatched by a build before this one
  carries no record and still keeps its slot past a handover (Task 20452).
- **A device on the latest release is no longer shown as a material "cannot be
  compared" skew under a hub running a build of main.** Version strings cannot
  order a release against a build of main, so the Executors panel and
  `cloop executor list` flagged every such device in red — through every rolling
  upgrade, and even under a hub at the release's own commit. Both builds carry
  their place on main, which orders them: the same sequence is no skew, an
  earlier one the new `older` class, which is not material on its own (the
  protocol check still flags a device whose agent lacks what the hub needs),
  and a later one `ahead` (Task 20452).
- **A command run against a database migrated past its binary says so once.**
  Every command first printed the whole refusal as an
  `executor: handle persistence unavailable` warning about surviving restarts,
  and then refused with the same sentence (Task 20452).

### Changed

- **Hub health no longer costs a doctor run and two identity-provider fetches
  per open administrator's tab every minute.** The header's indicator asked
  `GET /api/hub/health` again at each report's one-minute expiry, so every
  open tab made its member run the doctor's checks once a minute, and each
  run fetched the issuer's discovery document and key set: on :8888 the
  summary was 39% of all dashboard fetches, and a blip at Entra lit the
  warning while sign-ins went through. Now each member makes its own report
  every five minutes (`ui.hub_health_interval`, 1m–1h), when its
  configuration changes, after an executor, hub CA rotation or sealing-key
  change, and on Run the checks again. It pushes the summary (failing count,
  generation, when it was made and when the next is due) only to sockets whose
  identity holds `config.write` across the hub. That is re-checked when a
  session's claims change or a credential ends, and every 30 seconds, and a
  socket that loses the permission is told so. A page asks only when its
  socket opens, and while Settings → Hub health is on screen. The issuer the
  hub signs in with is read from its sign-in client's cache and last fetch
  error; while the client holds no usable resolution, a report asks it to try
  again at most every 15 minutes. Only an issuer the running process does not
  use is resolved by the report, at most every 15 minutes (`oidc.running` says
  why). New metrics:
  `cloop_hub_health_reports_total{trigger}` and
  `cloop_oidc_idp_fetches_total{document,client,outcome}` (Task 20446).

## [0.0.7] - 2026-10-27

Three things to know before upgrading. **Grants to a label selector issued on
an earlier build start delivering.** 0.0.6 accepted, listed and audited a grant
to `label:region=eu,gpu=true` and gave it to no run; 0.0.7 gives it to every
executor the hub records with those labels. List the grants whose subject
begins `label:` with `cloop secret grants` and `cloop egress list`, and revoke
the ones you did not mean to keep before you upgrade (Task 20432). **Executor
agents speak protocol v26**, against 0.0.6's v22: v23 hands the model relay's
CA to the harness, v24 reports firewall refusals, v25 takes two CAs during a
rotation and v26 answers the isolation probe. A device left on 0.0.6 keeps
running its work, but its runtimes stay unverified and its refusals unreported
until it is upgraded. **Migrations 0079–0082 are additive and guarded**: four
defaulted columns on `broker_keks` and four new tables created `IF NOT EXISTS`,
each recorded `additive`, so a 0.0.6 build sharing the database — a hub member
not yet upgraded, or a dashboard or `cloop run` left on an older build — still
opens it.

The release carries the security fixes `main` has made since 0.0.6: a build
with Go 1.26.10, for crypto/x509's GO-2026-6809 (Task 20440); a git proxy that
read a SHA-256 repository's ref delete as an update, so a session allowed to
update but not to delete could delete (Task 20436); dashboard model calls that
ran an agent on the hub's host on the hub's own Claude login (Task 20442); and
resumed and failed-over runs that acted on that login rather than on their
starter's (Task 20443). With them come verified isolation claims (Task 20439),
online rotation of the hub's CA (Task 20438), push scanning (Task 20436), the
model relay (Task 20435), firewall refusals and denial logs (Task 20437),
label-selector grants that deliver (Task 20432), sealing keys held in a KMS
(Task 20433), Hub health in Settings (Task 20434) and a `copilot` provider
(Task 20447). Read *Upgrading from 0.0.6* before upgrading a hub, a Helm release
or a device.

### Security

- **A run the hub carries on by itself acts on its starter's Claude account,
  not the hub's shared login.** The automatic resume after a usage cap — since
  Task 20440 after every exhausted five-hour window too — the cluster member a
  resume is handed to, and a failover's replacement dispatched with no
  environment resolver, so on a hub with sign-in a resumed run on the hub's
  host inherited the `cloop ui` process's own login and ambient token: on
  :8888 it ran on no `CLAUDE_CONFIG_DIR` of its own, while the run its starter
  pressed carried theirs. Each now acts for the person the control plane
  recorded starting the run (else the project's owner) and pins their Claude
  home exactly as their own Run does; an isolating executor still gets their
  grants through the broker. An older build's extra-usage pause clears by that
  person's own usage windows. The record names the run it was written for, so
  a `cloop run` started from a shell is not carried on as whoever last pressed
  Run on the hub. No home is ever created for a resume: when the starter's
  home is gone, they are denied (hub-wide or on the project) or left off the
  executor's access list, or nobody can be named, the run stays paused with
  the new reason
  `starter_unavailable` — "starter's Claude account unavailable" — naming
  them, journaled, and is not retried; whether and why the hub denies someone
  stays in its log. `run.cap_resumed` and `executor.failover` record
  `acted_for`, and a `tests/arch` gate refuses a production dispatch that
  passes no resolver (Task 20443).
- **The dashboard's model calls run where the project runs, on the caller's
  Claude account.** The Split preview, dictation's Revise, the blocker
  analysis and the plan assistant built the project's provider inside the hub
  and called it there. With claudecode, the default, that was `claude --print
  --permission-mode bypassPermissions` in the project directory with the hub's
  whole environment: on a hub with `executors.allow_host_process: false`, or
  for a project bound to a sandbox, anyone who could edit a task got an agent
  with every tool on the hub's host, prompted with text they wrote — and anyone
  who could read one, through the blocker analysis, which hung off a `GET`. On
  a hub with sign-in each spent the hub's own Claude login, not the caller's,
  and a sandboxed project's `base_url` could be sent an API key from the hub's
  environment. Each is now a cloop subcommand dispatched to the project's
  executor like a brainstorm, after the harness preflight (a sandbox with no
  Claude login is a 409 `harness_credential_missing`), with the caller's
  `CLAUDE_CONFIG_DIR` and no ambient token — in a sandbox, with none of the
  hub's environment; on the host executor, with what the project's own runs
  there get: `cloop task decompose --dry-run --json`, a hidden `cloop task
  revise`, `cloop task ai-blocker --json` and a hidden `cloop plan chat`, whose
  answer the hub relays as the executor delivers it. The analysis is `POST /api/tasks/{id}/blocker` (`task.mutate`);
  the `GET` only detects, and answers 405 to `analyze=true`. The provider-call
  and task replays, which still call a provider in the hub, are refused for a
  project bound to an isolating executor as well as under strict mode, and run
  on the caller's account; claudecode's retry after a 401 no longer swaps the
  hub's own refreshed token into a call pinned to another account.
  `tests/security`'s call-graph gate missed all of it because the calls went
  through the `provider.Provider` interface: it now resolves a call on any
  interface declared in the module to every implementation in the module, with
  the executor drivers still the boundary, which also brought the dashboard's
  offboarding and SCIM's delete under its gated-step proofs (Task 20442).
- **cloop is built with Go 1.26.10**, for GO-2026-6809 ("Distrust compromised
  intermediate certificates in crypto/x509"), which the hub CA's leaf
  verification reaches through `x509.Certificate.Verify`. Go 1.26.9 is
  affected. `go.mod` now pins `toolchain go1.26.10` (Task 20440).
- **A runtime's isolation claim is verified instead of believed.** An
  executor's `Virtualized` and `KernelIsolated` were read off its runtime's
  name, so a `daemon.json` alias or a RuntimeClass whose handler is runc ran a
  project that demanded a VM on the host kernel. The hub now runs `cloop
  isolation-probe` — the hub's or the agent's own binary, bound into the sandbox
  read-only so an image cannot fake it — under each executor's runtime when
  configured container and Kubernetes executors are reconciled, at a device's
  hello, after a runtime change (the Sandbox dialog, a virtual executor's
  definition), daily and on the card's Re-probe, and classifies what the kernel
  serving the sandbox said — uname, `/proc/version`, its boot ID, the CPU's
  hypervisor flag, the DMI vendor, gVisor's markers — against the executing
  host's own kernel as host-kernel, userspace-kernel, vm or unknown. A project
  requiring kernel isolation or virtualization is refused on an executor whose
  evidence contradicts its claim (constraint `isolation_evidence`, quoting the
  evidence); one never verified is admitted with a warning on the run, or
  refused under `executors.isolation_evidence: required`. Evidence is recorded
  per executor and runtime (migration 0082, a guarded new table the stable UI
  never reads); executor cards, the virtual-executor dialog and the Sandbox
  dialog say "claims kata, runs on the host kernel"; `cloop hub doctor` and Hub
  health check `executors.isolation`; a changed verdict is audited as
  `executor.isolation_verdict`; `cloop_executor_isolation_probes_total` counts
  the probes. Devices answer from protocol v26; an older agent is recorded as
  unverified, naming the upgrade (Task 20439).
- **The hub's own CA can be replaced online, and in an emergency at once.**
  Under `tls: auto` the CA the git proxy's and Kubernetes monitor's
  certificates come from was minted once, valid ten years, and never replaced:
  a suspected leak of its key — a backup taken with the root key, a misused KMS
  identity, a departed operator — had no remedy short of rebuilding the control
  plane. `cloop hub ca rotate --stage` mints a second CA sealed exactly as the
  first (under the KEK registry, under the KMS when `secrets.kms` is set,
  rewrapped by key rotation), and from then on every sandbox dispatched trusts
  both — git's per-URL `sslCAInfo` bundle, the kube monitor kubeconfig's
  `certificate-authority-data`, Node's CA file, a Pod's lease Secret, a
  device's or virtual executor's start frame — while each dispatch records which
  CAs it was given. `--activate` is refused while a run dispatched before the
  stage is still running, unless `--force`, which names the runs it breaks, and
  while a hub member has not adopted the stage or runs an older build; the
  cluster leader then reissues every leaf and every member serves it within a
  minute. `--retire-previous` drops the old CA from every bundle and destroys
  its sealed key with `secure_delete` (every write to `hub_tls` now runs with
  it). `--now` does all three with a fresh CA and every member ends the git
  proxy, Kubernetes monitor and model relay sessions of the runs that trusted
  only the replaced CAs, naming them. A CA a rotation mints carries X.509 name
  constraints for the monitors' names, so it cannot vouch for another host even
  to Node; moving an advertise URL to a new host is then a rotation. The same
  steps are in Settings → Hub health; `cloop hub doctor` warns about a stage
  that outlasts the longest `session_minutes`, a member that predates rotation,
  a name the CA does not permit, and a CA nearing expiry, naming the command;
  each step is audited (`hub_ca.rotation_staged`, `…_activated`,
  `hub_ca.previous_retired`, `…_abandoned`, `hub_ca.emergency_rotated`,
  `hub_ca.sessions_ended`) and metered (`cloop_hub_ca_*`). Agents speak
  protocol v25, which lets a device's harness take both CAs for Node; an older
  device's relayed run is handed the active CA alone and holds an activation
  back (Task 20438).

- **The git proxy refuses a push that carries a credential the run was
  given.** It used to decide on a push's command list and stream the pack to
  the forge unread, so a workload that committed its leased env secret, the
  token in its kubeconfig, its registry auth or its egress proxy's password
  published it through the one choke point every proxied push crosses — and
  GitHub's push protection knows vendor shapes, not an internal key granted as
  an env secret. The proxy now inflates every pack as it streams — commits,
  trees, blobs, tags, the bytes each delta inserts, ref names, push options —
  and matches the exact values the run's lease and spec delivered, as
  delivered, base64-encoded at every alignment and percent-encoded, plus as
  defence in depth the forge token it holds itself. The forge never gets the
  pack's checksum until the scan finds nothing; a push that carries one is
  aborted upstream, so receive-pack never sees a whole pack and no ref moves,
  and git prints each object, its path and commit, and the grant and secret
  the value came from, never the value. The refusal is a
  `gitproxy.push_secret_refused` audit row, a `git_push_refused` row in the
  run's history and a line in the task's details, counted in
  `cloop_gitproxy_push_scans_total`. `executors.git_proxy.push_scan` is
  `values` by default whenever the proxy runs, `shapes` to add pkg/redact's
  credential formats, or `off`; a project may tighten it, never loosen it; a
  push past `push_scan_max_object_mb`, `push_scan_max_push_mb` or
  `push_scan_seconds`, or a pack the proxy cannot read, is refused naming why.
  It stops an accident and a naive leak, not a workload transforming a value on
  purpose, and after a hub restart an adopted run is scanned only for its env
  secrets and PATs; the architecture page says what else it cannot see
  (Task 20436).
- **The git proxy reads a SHA-256 push's all-zero object id as zero.** It
  compared against SHA-1's forty zeros only, so a SHA-256 repository's delete
  read as an update — which a session that may update and not delete then
  allowed — and its create as an update too (Task 20436).
- **A sandboxed run's Claude credential can stay on the hub: the model relay.**
  With `executors.model_relay` on — it is off by default — a `claudecode` or
  `anthropic` run on a container, a Pod, an enrolled device or a virtual
  executor is no longer handed its Claude OAuth token. The hub mints a session
  on the run's secret lease, gives the sandbox `ANTHROPIC_BASE_URL` and a
  `cloop_relay_…` token in its place, and spends the credential against the API
  itself. The session ends with the lease, so revoking the grant reaches a
  running device task at its next model call, which a delivered variable never
  allowed; it survives a hub restart with its run, renews with the lease, and
  any cluster member serves it. The relay counts each response's usage from the
  API's own answer, charges it to whoever started the run in
  `daily_token_budget` and `daily_cost_usd`, refuses the next call once either
  is spent — with a `403` naming the cap, which Claude Code stops on rather than
  retrying — and when the run ends books the gap between its count and what the
  run reported (`model_relay.usage_gap`). The hub's model allowlist, which a
  project's maintainers can narrow from its Claude credential card, decides the
  models a run may call. It rides the git proxy's listener by default, the
  hub's CA handed to the harness's Node in a file of its own through
  `NODE_EXTRA_CA_CERTS` (agent protocol v23; an older device keeps today's
  delivery, and the run's history says so), or the dashboard's. Only credential
  kinds proven against the real API are relayed: an OAuth token is; an
  Anthropic API key still reaches the sandbox, and the card says *not relayed*.
  A relay that should serve a run and cannot, or a section that does not load,
  refuses the run rather than hand it the credential (Task 20435).
- **A grant to a label selector reaches the executors the hub records with
  those labels, and nothing a device says about itself counts.** A grant to
  `label:region=eu,gpu=true` was accepted, listed and audited, and delivered
  nothing: no dispatch path — a run's lease, its egress session, the workspace
  fetch, the Kubernetes driver's credential, the GitHub App picker, the
  harness-credential check, `hub doctor --smoke` — ever gave the broker the
  executor's labels. Every requester is now built by one constructor,
  `secretbroker.NewRequester`, from the hub's own record of the executor: an
  enrolled device's agent credential, a virtual executor's device's, a
  configured executor's new `executors.container.labels` or
  `executors.kubernetes.labels`. The labels a device's agent advertises at
  hello never count, and `tests/arch` fails on a requester assembled anywhere
  else. Leases and egress sessions record the labels they are judged by, so a
  run adopted after a restart is judged the same way, and the workspace fetch
  now honours label grants instead of the guide saying it did not. **A label
  grant issued on an earlier build starts delivering on this one:** before
  upgrading, list the grants whose subject begins `label:` (`cloop secret
  grants`, `cloop egress list`) and revoke any you did not mean to keep — after
  it, the Secrets panel shows which executors each one reaches (Task 20432).
- **Retiring a sealing key now erases it from the database file, not just from
  its row.** Retirement blanked a key-encryption key's salt and check value, but
  SQLite left the old bytes in the page's free space — as an earlier write to
  the key's row, a demotion or an attribution, could leave another image of it
  there — so a copy of the file taken afterwards still held a retired key's salt
  and, with `CLOOP_SECRET_KEY`, the key. Every write to the key registry now
  runs with secure delete on, which zeroes what it frees. What the write-ahead
  log holds of an old page lasts until the log is reused, an image a build
  before this one freed lasts until SQLite reuses its space, and a backup taken
  before the retirement keeps everything (Task 20433).

### Upgrading from 0.0.6

0.0.7 starts delivering grants 0.0.6 accepted and never delivered, and refuses
some pushes, connections and dashboard calls 0.0.6 let through. Act on *Before
you upgrade*, then upgrade every hub process on a control plane together, then
the edge devices, and run 0.0.7's `cloop hub doctor` right after.

#### Before you upgrade

- **Revoke the label grants you did not mean to keep.** On 0.0.7 a grant to a
  label selector reaches every executor the hub records with those labels — an
  enrolled device by its agent credential's labels, a virtual executor by its
  device's, a configured executor by `executors.container.labels` or
  `executors.kubernetes.labels` — on every credential path: a run's lease, its
  egress session, the workspace fetch, the GitHub App picker. List them with
  `cloop secret grants` and `cloop egress list` and revoke with `cloop secret
  revoke <grant-id>` or `cloop egress revoke <grant-id>`; after the upgrade the
  Secrets panel shows which executors each one reaches (Task 20432).
- **Back up: a rollback is a restore.** Migrations 0079–0082 add four defaulted
  columns to `broker_keks` and the tables `network_denials`,
  `hub_ca_rotations`, `hub_ca_members` and `isolation_evidence`, all created
  `IF NOT EXISTS` and recorded `additive`, so a 0.0.6 binary still opens and
  saves an upgraded database — and ignores what they hold: it places runs by
  their runtimes' names alone, records no firewall refusal and knows nothing of
  a CA rotation. Run `cloop db backup` in the hub's directory and in each
  project's (Tasks 20433, 20437, 20438, 20439).

#### Running 0.0.6 and 0.0.7 side by side

Members of one control plane can run both releases during the upgrade, but
0.0.7's fixes hold only on its own members:

- **A 0.0.6 member delivers no label grant**, runs the Split preview, Revise,
  the blocker analysis and the plan assistant inside the hub on the hub's own
  Claude login, and resumes a capped or failed-over run on that login rather
  than its starter's (Tasks 20432, 20442, 20443).
- **A 0.0.6 member's git proxy scans no push** and reads a SHA-256 repository's
  delete as an update (Task 20436).
- **Turn on `executors.model_relay` and `secrets.kms` only once every member
  runs 0.0.7.** A 0.0.6 member serves no relay session, and once a KMS holds a
  live key-encryption key a 0.0.6 member refuses to start or seal: the key's
  salt is a decoy no passphrase derives (Tasks 20433, 20435).
- **A CA rotation's `--activate` is refused while any member runs an older
  build** (Task 20438).

#### Executors and devices

- **A device on 0.0.6 speaks protocol v22 and keeps running its work.** A 0.0.7
  hub records its runtimes as unverified — a project requiring isolation is
  then admitted with a warning, or refused under
  `executors.isolation_evidence: required` — reports none of its sandboxes'
  firewall refusals, and relays none of its runs: they get their Claude
  credential as before, and the run's history says why. Press Upgrade on its
  row in the Executors panel (Tasks 20435, 20437, 20439).
- **The hub probes each runtime it can dispatch to**: a short-lived sandbox
  from the executor's own image, never a project's, runs `cloop isolation-probe`
  at every reconcile, a device's hello, a runtime change and daily (Task
  20439).
- **A sandbox's firewall refuses what it blocks** — a TCP reset, otherwise an
  ICMP "administratively prohibited" — where 0.0.6 dropped it, so a workload
  that waited out a timeout now fails at once. `drop_denied: true` on a rule set
  (`executors.container.egress_filter` for the hub's own executor) keeps the
  silent drop (Task 20437).

#### Operations, CLI and API

- **New routes**, for a path allowlist in front of the hub: `GET
  /api/hub/health`, `GET /api/hub/ca` and `POST /api/hub/ca/rotate`
  (`config.write`), `POST /api/tasks/{id}/blocker`, `GET
  /api/tasks/{id}/network`, `GET /api/firewall/blocked`, `GET
  /api/grants/matches`, `GET` and `PUT /api/executors/{id}/labels`, `POST
  /api/executors/{id}/isolation-probe` and `PUT
  /api/projects/{idx}/model-relay`. The model relay answers under
  `/_anthropic` on the git proxy's listener, or on the hub's own with
  `executors.model_relay.listener: dashboard` (Tasks 20432, 20434, 20435, 20437,
  20438, 20439, 20442).
- **The blocker analysis is a `POST`.** `GET
  /api/tasks/{id}/blocker?analyze=true` answers 405, and `cloop task ai-blocker
  --json` frames its report between `<<<cloop-json:begin>>>` and
  `<<<cloop-json:end>>>` (Task 20442).
- **The Split preview, Revise, the blocker analysis and the plan assistant run
  on the project's executor** on the caller's Claude account: a sandboxed
  project needs a Claude credential granted for them as for a run (409
  `harness_credential_missing`), and a provider-call or task replay is refused
  for a project bound to an isolating executor (Task 20442).
- **A resumed or failed-over run that cannot act for its starter stays
  paused** with the reason `starter_unavailable` — their Claude home gone, they
  denied or left off the executor's access list — and is not retried: someone
  starts it again (Task 20443).
- **The git proxy scans every push** (`executors.git_proxy.push_scan: values`,
  the default whenever the proxy runs): a push carrying a value the run was
  given is refused, as is one past `push_scan_max_object_mb` (1024),
  `push_scan_max_push_mb` (4096) or `push_scan_seconds` (300). `off` keeps
  0.0.6's behaviour; a project may tighten the scan, never loosen it (Task
  20436).
- **`budget.block_extra_usage` applies to `claudecode` runs only**, and its
  hold is a usage-cap pause the hub resumes when the window reopens (Task
  20440).
- **Cost reports and `daily_cost_usd`** count Claude Opus 4.5 and 4.6 at a
  third of what 0.0.6 counted and Haiku 4.5 at a quarter more (Task 20435).
- **Retire a KMS-held key with 0.0.7 or later**: an older `cloop hub key
  retire` leaves the KMS's ciphertext of the key behind (Task 20433).
- **Helm chart 0.5.0 → 0.6.0**: the `kms.*` values run a KMS v2 plugin
  sidecar or reach Vault Transit; `kms.enabled` is off by default, so a release
  upgraded with its old values behaves as before (Task 20433).
- **`cloop hub doctor`** checks `executors.isolation`, `secrets.kms.*` and the
  hub CA's rotation and expiry, and its probes honour `HTTPS_PROXY` (Tasks
  20433, 20434, 20438, 20439).

### Added

- **A `copilot` provider runs the GitHub Copilot CLI as the agent harness.**
  `provider: copilot` (or `--provider copilot`, the dashboard's provider
  pickers, `cloop init`, the review gate and `cloop router`) runs `copilot`
  once per call in prompt mode, under the sign-in the CLI already has —
  `copilot login`, `COPILOT_GITHUB_TOKEN`, or a model provider of its own via
  `COPILOT_PROVIDER_BASE_URL` — with the prompt on stdin, every tool allowed as
  `claudecode`'s `bypassPermissions` allows them, and no stopping to ask.
  `copilot.model` (`auto` lets Copilot pick) and `copilot.effort` pass through
  as `--model` and `--reasoning-effort`; each conversation gets an ID, so a
  task whose agent ends its turn early is resumed in it; token counts come from
  the CLI's usage report; the reviewer gets the reading tools only; and work
  the agent leaves running is waited for under `copilot.background`, by the
  same code as `claudecode`'s, now shared in `pkg/provider/agentproc`. A flag
  an older CLI does not know is dropped rather than failing every task. On an
  isolating executor the project needs `copilot` where it runs — devices
  advertise it from this build's agent on; it is not installed on request —
  and `COPILOT_GITHUB_TOKEN`
  (or the provider URL) granted: the hub refuses the dispatch without one, the
  Overview's *Copilot credential* card grants a pasted fine-grained token in a
  step and refuses classic, installation and refresh tokens with the reason,
  and a Copilot grant never supersedes the project's Claude one. Every command
  now reads a provider's configured model through one `config.ModelFor`
  (Task 20447).

- **Decompose, beside Add Task, plans a task into several before any is
  added.** A task too big for one agent could only be added whole and split
  afterwards, or retyped as a request in AI Feature Suggestions, where the
  priority and dependencies typed for it had no place. Decompose hands the
  title and description to the planner `cloop suggest --input` runs — on the
  project's executor, as the panel's Generate does — opens the panel, and
  empties the form once the hub has the job; the plan's steps are added one at
  a time or with Add all. `POST /api/suggest/generate` takes `priority` and
  `depends_on` for a plan, checked as Add Task checks them and refused for a
  brainstorm, and the job's status reports them: every task of the plan takes
  that priority and waits for those tasks as well as for the plan's own earlier
  steps, and one deleted before the plan is accepted is dropped rather than
  followed to whatever takes its ID. A pending task's Split dialog, now titled
  Split, loads on demand, and its result is no longer toasted over by
  "Refreshed" (Task 20441).

- **A connection a sandbox's firewall blocks fails at once, and the run says
  what blocked it.** The firewall ended in a silent drop, so a blocked fetch
  waited out a TCP timeout, the harness retried for minutes, and nothing said
  which address had been refused by which rule. Every deny path now refuses —
  a TCP reset (`ECONNREFUSED`), otherwise an ICMP "administratively
  prohibited" — and logs the packet, rate-limited, to an NFLOG group under a
  prefix naming the rule set's fingerprint and the rule. The hub reads it for
  its own container executor and each device's agent for its sandboxes
  (protocol v24, no privilege beyond the packet-filter grant), aggregates it
  per run by destination, port, protocol and rule — 64 itemised, the rest
  counted — and keeps addresses and ports only. A run's history gets `blocked
  203.0.113.7:443/tcp x14, not in the project's allow list` and a summary when
  it ends; the task's details get a Network section beside the egress proxy's
  refusals; the project's firewall card lists what was recently blocked, with
  **Propose allow rule** for admins, saved through the usual containment
  checks; and `run.firewall_denied` (one row per run and rule) and
  `cloop_firewall_denials_total` record it. `drop_denied` keeps the silent
  drop on any rule set, and a Kubernetes executor says its denials are not
  observable (Task 20437).

- **Settings → Hub health: the hub doctor's checks, run by the hub on itself.**
  `cloop hub doctor` ran only in a shell on the hub host, in its directory, with
  both configuration files in reach, so an administrator of a Helm or compose
  deployment never saw a hub CA nearing expiry, audit forwarding falling
  behind, a lagging edge device or an API token waiting for approval, and
  nothing said when one started failing. `GET /api/hub/health` (config.write)
  now runs the same checks inside the serving hub, against the configuration
  it runs under, overlay included, and names the cluster member that answered.
  It never runs `--smoke` or `--probe-network-policy`; it answers from what the
  hub already knows where the shell's doctor asks from outside — the executors
  it reconciled and its supervisor's record of each, its own sign-in instead of
  an unauthenticated request to its listener, the KMS clients it pinned — gives
  every check its own deadline and recovers its panics (`doctor.unfinished`,
  `doctor.panic`), caches a report for about a minute, makes its six heaviest
  checks at most every 15 minutes, and computes everything again when the
  configuration changes. Every value a check wrote is redacted — the exact
  credentials the configuration and environment hold, then the credential-shape
  registry — before the Settings panel shows it as text, grouped by severity
  with its remedy and its runbook section. Administrators get a header
  indicator while any check fails, refreshed by a `hub_health` push and when
  the report it read expires, with no poll of its own. Probes now honour
  `HTTPS_PROXY`, for `cloop hub doctor` too (Task 20434).
- **The secret store's sealing keys can be held by an external key-management
  service, so a copy of the database and the key file is no longer enough.**
  With `secrets.kms`, every key-encryption key is random and the database keeps
  only the ciphertext the KMS made of it: opening the store is a call to the KMS,
  which logs it and whose owner can revoke the hub's access. Two backends: a
  Kubernetes KMS v2 plugin over a unix socket — Azure Key Vault, AWS KMS, Google
  Cloud KMS and Vault through their vendors' plugins, run by the Helm chart as a
  sidecar (`kms.*` values) — and Vault or OpenBao Transit. Moving onto a KMS,
  off it or between two is a change of root, finished by `cloop hub key rotate
  --retire-previous` with every cluster member able to open the store
  throughout; a rotation of the KMS key is followed by rewrapping each key in
  place, by the cluster leader or `cloop hub key rewrap`. A hub that cannot reach
  its KMS refuses to start — never falling back to the passphrase — and `cloop
  hub doctor` reports `secrets.kms.*`; KMS calls are measured
  (`cloop_kms_requests_total`, `cloop_kms_request_duration_seconds`). Restore
  preflight and the key escrow say when a backup's keys need the KMS, and the
  Azure Terraform module gains `modules/key-vault-kms`, a wrap-and-unwrap key
  with the hub identity's permission on it alone. Retire KMS-held keys with this
  build or later: an older `cloop hub key retire` leaves the KMS's ciphertext of
  the key behind, which the hub destroys at its next start and the cluster
  leader at its next KMS poll (Task 20433).

- **Device labels can be changed on the hub, and the credentials they no longer
  qualify for are taken back from running work.** **Labels** on a device's card
  (`PUT /api/executors/{id}/labels`, audited as `executor.labels`) replaces the
  labels it was enrolled with; the device's running leases and egress sessions,
  and its virtual executors', are re-judged at once, and a label grant the new
  labels no longer match is taken back as a revoked grant is, from the hub's copy
  and every holder. Each hub member re-checks the leases it holds once a minute,
  which carries an edit made elsewhere, or a configuration the hub restarted
  with, to them. The Enroll dialog takes labels too, and labels no selector
  could name — a `,` in a value, a space in a key — are refused where they are
  typed (Task 20432).
- **The Secrets panel shows which executors a label grant reaches.** Each
  grant to a label selector lists the executors carrying its labels now, or
  says that none does; the grant dialog answers the same as the subject is
  typed (`GET /api/grants/matches`), and `cloop secret grant` and
  `cloop egress grant` print it. `cloop secret lease --executor` names the
  labels the hub records for the executor it dry-runs, and
  `cloop egress test --to executor:<id>` tests with them (Task 20432).

### Changed

- **`cloop task ai-blocker <id> --json` frames its report** between
  `<<<cloop-json:begin>>>` and `<<<cloop-json:end>>>`, as `cloop suggest --json`
  does, and reports a failure the same way, so the hub can read it back from
  the project's executor. A script that piped the bare JSON to a parser reads
  the lines between the markers instead (Task 20442).

### Fixed

- **The plan assistant answers when the project's provider is claudecode.** The
  assistant relayed only what the provider streamed token by token and dropped
  the finished answer, and claudecode streams nothing, so with the default
  provider every question came back empty. The answer now arrives whole when
  nothing was streamed (Task 20442).

- **A run held back to avoid extra usage carries on when its window reopens.**
  `budget.block_extra_usage` (on by default) stopped a run whose Claude Code
  five-hour or weekly window was used up from inside the daily budget check, so
  it was recorded as a spent budget with no reset time. The hub never resumes a
  spent budget on a timer, so the project sat paused until somebody pressed
  Run, although the window reopened within hours. The hold is now a
  subscription cap like `claudecode.max_*_pct`: a window that reopens within 90
  minutes is waited out in place, and a later one pauses with its reset
  recorded ("Paused: 5-hour window exhausted, resumes 23:30"), which the hub's
  auto-resume acts on. It also applies only to `claudecode` runs now. A pause
  an older build recorded the old way is resumed by the hub once the usage API
  shows the window open. A snapshot older than its window's reset no longer
  holds a run. An auto-evolve round is held the same way: a plan that drained
  as its window ran out used to send the round into the wall and, after three
  empty answers, close the run as complete, which nothing resumes. A round the
  provider answers with a limit message now waits or pauses on its reset. Claude Code's "You've hit your session limit · resets 11:30pm
  (UTC)" is recognised, so a task the limit cuts off goes back to pending and
  is retried after the reset instead of being recorded as done; other "you've
  hit your … limit" and "… limit reached · resets" wordings are recognised by
  shape. A reset is read in the time zone the message names rather than
  always as UTC (Task 20440).
- **IPv6 works behind a sandbox firewall.** The bridge filter's hook for
  traffic to the host covered the multicast and link-local ranges neighbour
  discovery uses, so a sandbox on an IPv6-enabled network could not resolve its
  gateway and every IPv6 connect failed with "no route to host". Neighbour
  discovery and multicast listener reports with this host are now let through
  (Task 20437).
- **A device's ID never begins with a dash.** One enrollment in 64 minted an
  agent, enrollment-token or workload ID starting with `-`, which `cloop
  executor revoke` and every other command taking one read as a flag
  (`unknown shorthand flag`). Such IDs are now drawn again; one already minted
  still works after `--` (`cloop executor revoke -- -B63De5I_6wwcG6R`)
  (Task 20437).

- **A refusal Claude Code words as a failed sign-in is no longer retried as
  one.** Claude Code prints "Failed to authenticate" for a `403` as for a
  `401`, so the `claudecode` provider refreshed the credential and launched the
  CLI a second time for refusals a refresh cannot change — the model relay's
  spent budget among them — and reported them as authentication failures
  "retried once after refreshing credentials". A `403` is now reported once,
  as the refusal it is (Task 20435).
- **Claude Opus 4.5 and 4.6 and Claude Haiku 4.5 are priced as Anthropic bills
  them.** The price table charged Opus 4.5 and 4.6 at $15 and $75 per million
  input and output tokens — three times the $5 and $25 the API bills — and
  Haiku 4.5 at Haiku 3.5's $0.80 and $4 rather than $1 and $5, so cost reports
  and `daily_cost_usd` overstated the one and understated the other
  (Task 20435).
- **Reading the provisioned directory no longer takes the database's write
  lock.** The SCIM directory was read inside a plain transaction, which the
  connection policy begins `IMMEDIATE`, so every reader of it — the hub's
  version checks, `cloop hub doctor`'s `scim.directory` — queued behind and
  blocked the hub's writers for the length of the read. It is now a read-only
  transaction: the same consistent snapshot, without the writer's lock
  (Task 20434).

## [0.0.6] - 2026-10-16

The release that carries the security fixes `main` has made since 0.0.5 — GitHub
credentials that went to whatever host a project's origin named (Task 20423),
project images edge devices ran unverified under `require_signature`, CLI
cordons that took nothing back and a push token the harness could read (Task
20424), admin API tokens anyone could mint while no role policy existed, a SCIM
lockout anyone could trigger and git-proxy sessions that outlived their run
(Task 20422), and a root key that could be changed only by re-minting every
secret (Task 20425) — together with device forwarders, which bring an on-prem
USB device or network segment to a sandbox on a remote executor (Tasks 20429,
20430), audit forwarding (Task 20426), an approvals inbox (Task 20427) and task
attachments (Task 20428). Executor protocol **v22**, against 0.0.5's v21. Read
*Upgrading from 0.0.5* before upgrading: the first start suspends API tokens and
removes Claude logins that 0.0.5 kept.

### Security

- **A brokered GitHub credential goes only to the host its grant is for.**
  Repository allowlists matched `owner/name` and threw the host away, so a
  project whose origin was `https://attacker.example/acme/tool` matched a grant
  for `acme/*` and was sent its token: in the fetch's `extraHeader`, the
  write-back push, a pinned git-proxy session's upstream, and a feature's push
  and pull request. A GitHub Enterprise Server App grant was proxied to
  `https://github.com`, and a PAT minted for an internal server was presented to
  github.com for any github.com URL with the same `owner/name`. A repository is
  now a host and a path wherever a credential is chosen or bound
  (`pkg/forgehost` folds case, one trailing dot, userinfo, the default port and
  IDN; another port, another label or a look-alike is another host). A
  `github_pat` is for github.com unless minted for an Enterprise Server with
  `cloop secret mint --kind github_pat --github-host <host>` (a `{"token": …,
  "host": …}` payload); an App is bound to the host of its `base_url`
  (`https://<host>/api/v3`, or `https://api.<host>`). The git proxy serves other
  hosts under `/_forge/<host>/`, an Enterprise token is exported as
  `GH_ENTERPRISE_TOKEN`, never `GITHUB_TOKEN`/`GH_TOKEN`, and a mismatch refuses
  the dispatch with 409 `workspace_grant_missing`, naming both hosts. See
  *GitHub Enterprise Server* in `docs/guides/secrets.md` (Task 20423).
- **`sandbox.image_policy.require_signature` holds on edge devices and virtual
  executors.** It held on the hub's container and Kubernetes executors only: a
  device in container mode, and every virtual executor, ran project images that
  had passed the allowlists and nothing more, and a hub config that would not
  load was read as no policy at all. The hub now resolves a device's tag at its
  registry, verifies that digest with cosign and sends the device the digest,
  which its engine must already hold: it never pulls. Registry logins come from
  the hub user's Docker-format files (`~/.docker/config.json` or
  `$DOCKER_CONFIG`, `$REGISTRY_AUTH_FILE`,
  `$XDG_RUNTIME_DIR/containers/auth.json`); credential helpers are not run.
  Every way of not verifying refuses the run with 409 `sandbox_image_denied`,
  audited as `sandbox.image_denied`, and a hub config that cannot be read
  refuses every project that names an image, on every executor kind. Operator
  images — `executors.*.image`, a device's or virtual executor's own — stay
  exempt. `cloop hub doctor` fails `images.signature` when signatures are
  required, devices run project images and cosign is missing (Task 20424).
- **`cloop executor cordon`, `drain` and `revoke` take back what an edge device
  holds.** The dashboard's cordon and drain took a device's leases back; the CLI
  wrote the scheduler row and stopped — on a device it failed outright with
  `executor not registered` — and `revoke` left the agent connected until it
  next reconnected, although the runbook's incident response sends operators to
  these commands. They now record a revocation of every lease issued to the
  device and its virtual executors, announce it to the hub's members, wait up to
  30 seconds for their answers and print which member holds the device's
  connection and what came of each lease; that member scrubs the leases, and
  after `revoke` every member drops the agent. With no hub serving they say so,
  and the next hub's janitor enforces what was recorded; every member's janitor
  also drops a connected agent whose credential is revoked, within a minute. The
  commands write `executor.cordon`, `executor.drain`, `executor.uncordon` and
  `executor.revoke` audit rows, and the dashboard's delete takes a device's
  leases back before dropping it (Task 20424).
- **The harness cannot read a Kubernetes push write-back's forge token.** `cloop
  workspace writeback` removed the token from its environment with
  `os.Unsetenv`, which changes Go's copy only: the kernel went on serving it at
  `/proc/<pid>/environ` to the harness the wrapper starts, running as the same
  user. The wrapper, and `cloop workspace provision`, now make themselves
  non-dumpable once they hold a token, so their `/proc` entries belong to root
  and their memory cannot be traced without `CAP_SYS_PTRACE` (Task 20424).
- **An API token minted while no role policy was in force is suspended once one
  is.** With sign-in but no role policy every signed-in identity holds every
  role, so anybody could mint an admin token from the dashboard, and it stayed
  admin for up to a year after a policy was enforced. Each mint now records what
  governed it (migration 0071). On a hub that enforces a role policy
  (`ui.oidc.role_mappings` or `default_role`), an owner-less token minted
  without one — or before this release, which recorded nothing — answers 403 and
  is listed `suspended` until an administrator who holds its roles approves it:
  Secrets → API tokens → **Approve**, `POST /api/tokens/{id}/approve` or `cloop
  hub token approve <id>`. Tokens with an owner, tokens minted under the policy
  and tokens minted from now on with `cloop hub token create` keep working. The
  *Enforce deny-by-default* dialog lists the tokens it will suspend, and `cloop
  hub doctor` fails `api_tokens.unapproved` while one waits (Task 20422).
- **An offboarded identity's Claude login is removed from every hub member.**
  Offboarding reached only the members that answered it, so a stopped or silent
  member kept the person's Claude home and its plaintext refresh token. Every
  member now logs out (where it may) and removes, as it starts and hourly after,
  the Claude home of every identity denied hub-wide, auditing each as
  `user.claude_home_swept`. A legal hold keeps the home, and so does a SCIM
  suspension still in force; `cloop hub user offboard --keep-credentials` now
  places its hold before it denies anything. `cloop hub doctor` fails
  `offboard.claude_homes` while such a home is left on its host (Task 20422).
- **Somebody else's wrong guesses can no longer lock SCIM provisioning out.**
  SCIM answered 429 before it checked the bearer and shared the per-address
  lockout with the dashboard's token sign-in, so five wrong guesses from the
  identity provider's shared egress address — or from anywhere behind a proxy
  not in `ui.trusted_proxies` — locked provisioning out, and every suspension
  the provider sent with it. The credential is checked first now, and a valid
  one is served whatever its address's lockout says; only wrong credentials
  count, in a bucket of SCIM's own, and the fifth starts a 60-second lockout in
  which a wrong credential is answered 429 with `Retry-After`. An unknown
  credential id answers in a wrong secret's time, and a credential store that
  cannot be read answers 503, which providers retry, instead of counting against
  the caller (Task 20422).
- **A workspace's git-proxy session ends with its run.** A session the sandbox
  had used stayed valid for its full TTL after the run ended —
  `executors.git_proxy.session_minutes`, 60 minutes by default and up to 12
  hours — for anything that had lifted its token. It now closes, with its lease,
  once the workload is terminal and its write-back has run or been abandoned,
  and is renewed while the run lives instead (migration 0072, audited as
  `gitproxy.session_renewed`), so a run longer than `session_minutes` can push
  its write-back (Task 20422).
- **The dashboard asks before every `DELETE` it sends, and the GitHub App
  panel's controls act only inside the panel.** The panel answered clicks from
  one listener on the whole document, so an element carrying `data-gh-revoke`
  anywhere on the page — markup in a task's output, say — revoked a project's
  repository grant, and neither that revoke nor deleting a knowledge-base entry
  asked first. Both now ask, naming what goes, and
  `TestDashboard_EveryDeleteIsConfirmed` holds every `DELETE` in every script
  the hub serves to a confirmation (Task 20422).
- **`CLOOP_SECRET_KEY` can be changed online, and kept out of the environment.**
  Every key-encryption key derives from it, so changing it was an eight-step
  re-mint of every secret and grant, and it could live only in the process
  environment: `/proc/<pid>/environ`, `docker inspect`, `kubectl get pod -o
  yaml` and every child not scrubbed of it. One resolver (`pkg/rootkey`) now
  reads it from `CLOOP_SECRET_KEY_FILE` — a regular file the hub's user owns,
  mode 0400 or 0600, outside every `.cloop/` — then the systemd credential
  `cloop-secret-key` (`LoadCredential=` or `LoadCredentialEncrypted=`), then the
  environment; sources that disagree are refused, never ranked. During a change
  the previous key (`CLOOP_SECRET_KEY_PREVIOUS`,
  `CLOOP_SECRET_KEY_PREVIOUS_FILE` or `cloop-secret-key-previous`) only opens:
  roll the new key out to every hub member with the old one as previous, escrow
  it, and run `cloop hub key rotate --retire-previous`, which waits for every
  live member to run on the new key, rewraps every secret, session refresh token
  and hub CA key, and retires every key of the old one (migration 0073, audited
  as `sealing_key.root_changed`). Audit checkpoints, backups and
  `.cloop/secrets.enc` open under either key. `cloop ui` prints the key's source
  and fingerprint at startup, and refuses to start on a refused source or on a
  live key-encryption key no configured key derives. See *The root key* and
  *Changing `CLOOP_SECRET_KEY` itself* in `docs/operations/runbook.md` (Task
  20425). A key file owned by root is accepted only in the shapes Kubernetes and
  systemd make: readable through a group the hub is in, or through an ACL that
  lets the hub's user alone read it, which is how systemd 255 and later hand a
  unit with `User=` its credentials (Task 20431).

### Upgrading from 0.0.5

0.0.6 suspends API tokens, removes Claude logins and refuses GitHub credentials
and project images that 0.0.5 let through. Act on *Before you upgrade*, then
upgrade every hub process on a control plane together, then the edge devices,
and run 0.0.6's `cloop hub doctor` right after.

#### Before you upgrade

- **Back up: a rollback is a restore.** Migrations 0071–0078 only add columns
  with defaults and new tables, so a 0.0.5 binary still opens an upgraded
  database — and ignores what they hold: it accepts the API tokens 0.0.6
  suspends, restores a renewed git-proxy session only within its first period,
  dispatches a project bound to a device forwarder without the device, leaves
  attachments behind, and prunes audit rows no sink has received. Run `cloop db
  backup` in the hub's directory and in each project's; it does not copy
  attachment files, which `cloop snapshot save` does (Tasks 20422, 20426, 20428,
  20430).
- **Place a legal hold on every Claude login you must keep.** On its first start
  every 0.0.6 member logs out and deletes the Claude home of each identity
  denied hub-wide, unless a legal hold names it — including the homes a 0.0.5
  `--keep-credentials` offboarding kept, which recorded no hold, and those of
  identities denied with a hub-wide `cloop hub role revoke`. Find them with
  `cloop hub role list` and run `cloop hub user hold place <email|sub:subject>`
  for each before upgrading; a deleted home cannot be restored (Task 20422).
- **On a hub with sign-in and a role policy, approve or revoke the API tokens
  0.0.5 minted without an owner.** All of them are suspended from the first
  request (403), those made with `cloop hub token create` included, which stops
  the CI pipelines and scripts that use them. 0.0.6's `cloop hub token list`
  marks them `(unapproved)` and its `cloop hub token approve <id>` approves one;
  it migrates the database as it opens it, so this can be done before the hubs
  restart (Task 20422).
- **Mint GitHub PATs for an Enterprise Server or another internal server
  again.** A `github_pat` minted without a host is now for github.com alone, and
  a project elsewhere whose `owner/name` its grant admits is refused (409
  `workspace_grant_missing`) rather than sent the token. Mint one with `cloop
  secret mint --kind github_pat --github-host <host>` — a secret's host is fixed
  when it is minted, so under a new name, or after deleting the old one — and
  grant it again. An App grant for an Enterprise Server needs `base_url`
  `https://<host>/api/v3`. A project on another forge, GitLab say, no longer
  receives a GitHub token at all, and runs in flight whose recorded git session
  depends on such a credential are refused when a hub restores them (Task
  20423).
- **Give the hub cosign if it enforces signatures and devices run project
  images.** Under `require_signature` each such image now needs cosign on every
  hub member that holds device sessions (the published hub image has none),
  HTTPS from the hub to the registry, and for a private repository a login in
  the hub user's Docker config; and the device must already hold the exact
  digest its tag points at (Task 20424).

#### Running 0.0.5 and 0.0.6 side by side

Members of one control plane can run both releases during the upgrade, but
0.0.6's fixes hold only on its own members:

- **A 0.0.5 member knows no forge hosts.** It presents any GitHub grant's token
  wherever a project's origin points, and an Enterprise Server PAT minted with
  `--github-host` — whose payload is now a document naming its host — as that
  whole document, the Enterprise token inside it included, to github.com and to
  the origin. Mint such PATs only once no 0.0.5 member shares the control plane
  (Task 20423).
- **A 0.0.5 member** accepts every token 0.0.6 suspends; skips the signature
  check on a device's runs while it holds the device's session, wherever the
  request arrived; ignores the CLI's cordon, drain and revoke announcements,
  which then list it as silent; and dispatches a project bound to a device
  forwarder without the device, recording nothing (Tasks 20422, 20424, 20430).
- **A 0.0.5 leader** forwards no audit rows and sends no approval notifications,
  and a 0.0.5 `cloop hub audit prune` or `cloop db maintain` prunes rows no sink
  has received, which the next 0.0.6 leader records as
  `audit.forward.discontinuity`. A settings save or `cloop config set` by 0.0.5
  rewrites `config.yaml` without `audit.forward` and `notifications` (Tasks
  20426, 20427).
- **A 0.0.5 member reads the root key from the environment only.** Keep
  `CLOOP_SECRET_KEY` there — a copy that agrees with a key file is accepted —
  until every member runs 0.0.6, and finish a change of root only then:
  `--retire-previous` refuses while a member advertises no root key, and a 0.0.5
  member without the old key erases the session refresh tokens it cannot open
  (Task 20425).
- **A 0.0.5 member that adopts a run** lets its renewed git-proxy session lapse
  after its first period, failing the write-back; and a device forwarder that
  dials a 0.0.5 hub with sign-in is refused (401) and exits (Tasks 20422,
  20429).

#### Keys, credentials and tokens

- **The key in the environment keeps working**; moving it to a file is optional,
  and `cloop hub doctor` warns (`secret_key.source`) about a variable on a host
  systemd runs. Newly refused at startup: two sources holding different keys — a
  stray `CLOOP_SECRET_KEY_FILE` or `CREDENTIALS_DIRECTORY` included — a key file
  another user can read or replace, a previous key without a current one, and a
  live key-encryption key that no configured key derives, which 0.0.5 started
  beside anyway (Task 20425).
- **Helm chart 0.4.1 → 0.5.0**: with `secrets.existingSecret`, keep the key
  under `CLOOP_SECRET_KEY` and without a trailing newline (the file reader drops
  one, which makes it another key), keep `podSecurityContext.fsGroup`, and do
  not run the Pod as root; changing that Secret does not restart the Pods (Task
  20425).
- **A new bootstrap's `hub.env` no longer holds the key**: point a shell at the
  key file with `CLOOP_SECRET_KEY_FILE` (Task 20425).
- **Approving or denying a grant request now also needs `secret.grant` on the
  request's subject**: a hub-wide holder denied on that project or executor gets
  403 (Task 20427).
- **GitHub host rules**: a wildcard Enterprise grant exports
  `GH_ENTERPRISE_TOKEN`, not `GITHUB_TOKEN`; `cloop feature pr --token` goes to
  a host other than github.com only when `--api-url` names it; an origin spelled
  with another port, or as `www.github.com`, is another host (Task 20423).

#### Executors and devices

- **A device on 0.0.5 speaks protocol v21 and keeps running its ordinary work.**
  A run for a project bound to a device forwarder is refused on it (409
  `executor_unsupported`, naming the upgrade): press Upgrade on its row in the
  Executors panel (Task 20430).
- **The agent unit `cloop executor agent install` writes cannot attach a
  forwarded device.** A USB device needs `vhci_hcd` and write access to
  `/sys/devices/platform/vhci_hcd.0/attach`, an L2 segment a root agent with
  `/dev/net/tun`; override the hardened unit on executors that take them. The
  forwarder needs root, `usbip` and `usbip-host` for USB and `CAP_NET_RAW` for
  L2. Restarting the hub member that holds an agent's or a forwarder's
  connection detaches the devices of running runs, which continue without them
  (Tasks 20429, 20430).
- **`cloop executor cordon`, `drain` and `revoke` now take credentials back** —
  in-flight tasks keep running without their file-delivered credentials, and
  `uncordon` restores none — and may wait up to 30 seconds for the hub's
  members. `cloop executor ls` lists devices and virtual executors (Task 20424).
- **A hub config that cannot be read refuses every project that names an
  image**, on every executor kind, and with `default_registry` set devices
  receive fully qualified image names (Task 20424).
- **A root agent whose work root another user owns runs container workloads as
  that user** (Task 20430).

#### Operations, CLI and API

- **New routes**, for a path allowlist in front of the hub: the forwarder's
  WebSocket `GET /api/forwarders/connect`, authenticated by the forwarder's own
  token before the hub's sign-in (pass the upgrade and `Authorization` through),
  `/api/forwarders/*`, `/api/projects/{idx}/forwarders`, `/api/approvals`,
  `/api/approvals/count`, `/api/config/notifications`,
  `/api/tasks/{id}/attachments` and `POST /api/tokens/{id}/approve`; a cluster's
  members also open `/api/internal/cluster/forwarders/stream` to each other
  (Tasks 20422, 20427, 20428, 20430).
- **A stalled audit sink holds back audit retention.** `cloop hub audit prune`
  and `cloop db maintain` stop at the slowest sink and name it: remove a dead
  sink, or prune past it with `--force` or `--force-audit-prune`. A new sink
  sends every row still held, oldest first (`start: oldest`). Give every member
  the same `audit.forward` and `notifications`; a scheduled `cloop audit-log
  export | logger` beside a sink sends every row twice — deduplicate on
  `row_hash` (Task 20426).
- **A JSONL audit export's `payload` may now be a string**: one Go's encoder
  would rewrite is exported as the exact text stored (Task 20426).
- **`cloop hub doctor` fails** `api_tokens.unapproved`, `offboard.claude_homes`,
  `images.signature` (devices without cosign), `secret_key.source` (a refused
  key source) and `audit.forward.sink`, and warns `audit.forward` on a hub
  without sinks (Tasks 20422, 20424, 20425, 20426).
- **`cloop audit` scans `.cloop/attachments`** too, and exits 1 on a credential
  an agent attached (Task 20428).
- **`cloop db backup` does not copy attachment files**: after restoring one,
  their downloads answer 410 (Task 20428).
- **An `audit.checkpoints.file` placed directly in a mount point** lands on the
  root disk while the volume is not mounted: move it into a subdirectory that
  exists only on the volume (Task 20426).

### Added

- **Device forwarders bring an on-prem USB device or network segment to a
  sandbox on a remote executor.** For an agent that runs isolated in the cloud
  with limited access to on-prem hardware, the machine wired to the hardware
  runs `cloop forward`: it bridges exactly one configured USB device — as a
  USB/IP server that runs no `usbipd` and opens no port — or one network
  interface, through a promiscuous `AF_PACKET` socket, over one outbound,
  authenticated WebSocket to the hub, and runs nothing else. An administrator
  enrolls it (Executors → **Device forwarders**, or `cloop forward enroll`, with
  a single-use token) and binds its device to a project, optionally to one
  virtual executor, for 24 hours by default and 90 days at most (`cloop forward
  bind`); a maintainer asks for a binding through the request flow. At dispatch
  the hub relays the forwarder's stream to the executor that runs the sandbox,
  over the agent's own connection (protocol v22); the agent attaches the device
  through `vhci_hcd` or a TAP and gives it to the sandbox alone, and nothing
  listens on a port anywhere. A bound forwarder that is offline refuses the run
  (409 `forwarder_offline`), and so do host-process runs, gVisor and Kata
  sandboxes and agents that cannot attach the device; it is detached when the
  run ends, when the binding or the forwarder is revoked and when either side
  disconnects, on every member of a hub cluster. Enrollments, bindings, attaches
  and detaches are audited (`forwarder.*`), and the project's Overview lists its
  **Forwarded devices** (migrations 0077, 0078). See
  `docs/guides/device-forwarders.md` (Tasks 20429, 20430).
- **The audit trail is shipped off the box as it is written.** `audit.forward`
  makes the hub cluster's leader send every row of every audit chain — the
  control plane's and each registered project's — to syslog over TLS (RFC 5424
  in RFC 5425 framing, JSON or CEF), to an HTTPS endpoint (NDJSON, or Splunk
  HEC) or to a file outside every `.cloop/`. Each sink has a cursor per chain
  (migration 0074), advanced only once the sink acknowledges, so delivery is at
  least once with `row_hash` as the idempotency key, and every record carries
  `prev_hash` and `row_hash` for the receiver to check (`cloop hub audit forward
  verify`). A chain that no longer continues from a cursor is recorded as
  `audit.forward.discontinuity`, a change of sinks as
  `audit.forward.configured`. Credentials are named shared `env` secrets;
  plaintext is refused except to loopback with `allow_plaintext_loopback`, and
  cloud metadata addresses are refused at the dial. `cloop hub audit forward
  status`, `cloop hub doctor` and three `cloop_audit_forward_*` metrics report
  how far each sink has got. See *Forwarding the trail off the box* in
  `docs/operations/runbook.md` (Task 20426).
- **An approvals inbox tells approvers what waits on them.** A grant request
  lapsed after 72 hours unless somebody happened to open the Secrets tab, and a
  suspended API token waited on an administrator nobody told. A header badge now
  counts what the signed-in user may decide and opens the inbox (`GET
  /api/approvals`, `/api/approvals/count`); `cloop remote approvals
  list|approve|deny` decides from a `cloop login` session; and
  `notifications.webhooks` — Slack, Teams, Discord or plain JSON, set in the
  config or Settings → **Notifications** — is told when a request is filed,
  twelve hours before it lapses, when it is approved, denied, withdrawn or
  lapses, and when a token waits. The cluster leader sends each notice once
  (migration 0075), over https only and to no private address unless
  `allow_addresses` names it (Task 20427).
- **Task attachments: the files a run makes for a person.** A Claude Code
  attempt gets an outbox — `.cloop/attachments/outbox/<task id>/`, named in its
  prompt and in `$CLOOP_TASK_ATTACHMENTS` — and what it copies there, a report,
  a chart, a screenshot, a log, is attached to the task when the attempt ends,
  scrubbed of the run's leased credentials, up to 32 MiB a file, 100 files and
  128 MiB a task and 1 GiB a project (migration 0076). The task's details
  preview images and text and download anything, served as an attachment under a
  sandboxing CSP. Runs on remote executors, in Kubernetes and in containerised
  features carry up to 384 KiB of files back and record the rest as left on the
  executor. `cloop task attachments list|add|get|remove` manages them from the
  command line. See `docs/guides/attachments.md` (Task 20428).

### Changed

- **Executor protocol v22.** Device channels (`device_open`, `device_opened`,
  `device_data`, `device_close`) carry a device forwarder's stream to the agent
  over its own connection. Agents speaking v21 keep running ordinary work; a run
  that needs a forwarded device is refused on them, naming the upgrade (Task
  20430).
- **`cloop hub bootstrap` keeps the root key out of `hub.env`.** It writes
  `cloop-secret-key` beside `.cloop/` — sealed with `systemd-creds` into
  `cloop-secret-key.cred` where the host can (`--systemd-creds
  auto|always|never`), mode 0600 otherwise — and prints a unit that loads it
  with `LoadCredential(Encrypted)=`. `cloop hub key escrow import` writes a
  recovered key back to that file (Task 20425).
- **The Helm chart hands the hub its root key as a file.** It mounts the
  Secret's `CLOOP_SECRET_KEY` at `/etc/cloop/root-key/cloop-secret-key`, sets
  `CLOOP_SECRET_KEY_FILE` and blanks the variable `envFrom` would set, takes
  `secrets.previousSecretKey` for a change of root, restarts the Pods when its
  own Secret changes, and writes that Secret as `data`, so a value removed from
  the chart's values is removed from the Secret on upgrade (Task 20425). The
  chart is 0.5.0; this change had left it at 0.4.1 (Task 20431).
- **A root agent hands each container workspace to its work root's owner**, so
  its sandboxes run unprivileged; an agent running as root with a work root
  another user owns had its container runs refused (Task 20430).
- **Every residual risk in the security model's *What is not mitigated* cites
  the test or code that pins it.** Five of the 21 paragraphs had stopped
  describing the code; `TestEveryResidualRiskCitesEvidence` now fails CI on a
  paragraph that cites nothing that exists, so the fix that retires a residual
  cannot land until its paragraph is rewritten (Task 20424).
- **CI fails a feature or fix that has no changelog entry.** After 0.0.5 thirty
  commits landed with `[Unreleased]` empty, the security fixes of Tasks 20422 to
  20425 among them, so the Released installer workflow's 14-day gate on
  unreleased security fixes read nothing and passed. CI's new **Every feature
  and fix has a changelog entry** job (`scripts/changelog-coverage.py`, or `make
  changelog-check` before pushing) lists the commits since the latest release
  tag, merged ones included, and fails when a `feat`, `fix` or `perf` commit
  names a task, `(Task N)`, that no line added to `CHANGELOG.md` since the tag
  names in `[Unreleased]` or in the release being cut, or names no task and adds
  no line itself. `docs`, `test`, `ci` and `release` commits are exempt (Task
  20431).
- **CI tests `pkg/orchestrator` in two shard jobs of its own**, as it does
  `pkg/ui`, after the package passed 60% of the race step's time budget (Task
  20428).

### Fixed

- **A session renewal no longer erases a refresh token the member cannot open.**
  A hub member renewing a browser session without the key that sealed its
  refresh token wrote an empty value over it, so the session could no longer be
  renewed in the background; the sealed token is now left as it is (Task 20425).
- **An exported audit row's hash can be recomputed from the export.** A payload
  Go's JSON encoder would rewrite — whitespace, `<`, `>`, `&` — was exported
  re-encoded, so neither a receiver nor the prune archive's verifier could
  recompute its `row_hash` from the record; it is now exported as a string
  holding exactly the stored text (Task 20426).
- **A newer agent no longer drops its connection to an older hub when somebody
  opens a sandbox shell.** The agent stamped its attach frames with the newest
  protocol it spoke rather than the one it negotiated, and a hub that does not
  speak that version closes the whole session (Task 20430).

## [0.0.5] - 2026-10-12

The first release since 0.0.4, about three hundred commits later. It carries the
security fixes `main` has accumulated since — among them a hub without sign-in
reachable from the network (Task 20393), web pages that could drive a hub
across sites and through DNS rebinding (Task 20394), stored XSS through a
project's name (Task 20408), project directories that could take in the hub's
own state (Task 20418), revocations that never reached running workloads (Task
20403) and offboarding that left a person's credentials on the hub (Task
20400) — and executor protocol **v21**, against 0.0.4's v13: virtual executors
(v14), firewall rules stored in the hub (v15), feature branches (v16), secret
refresh (v17), the hub's egress route (v18), exact grant revocation (v19), disk
limits (v20) and the hub's CA for `tls: auto` git proxies (v21). It is the first
release stamped with its place on `main`, so a device that runs it is covered by
rollback protection. Read *Upgrading from 0.0.4* before upgrading a hub, a Helm
release or a device.

### Security

- **A hub without sign-in listens on loopback only.** `cloop ui` bound every
  interface whatever its authentication, so a hub with neither `ui.oidc` nor
  a static `--token`/`CLOOP_UI_TOKEN` let anyone who could reach the machine
  list its projects and start agent runs on it. Such a hub now binds
  `127.0.0.1`; one with sign-in still binds every interface, and API tokens
  do not count as sign-in. `--listen`/`ui.listen` name an address; one
  beyond loopback without sign-in is refused at startup unless
  `ui.allow_unauthenticated_network: true`, which then warns at every start.
  `cloop serve` follows the same rule with its own token, and `cloop hub
  doctor` reports where a hub is actually reachable (`ui.exposure`). The
  image, the Helm chart and the compose stack pass `--listen 0.0.0.0`, so the
  image refuses to start without sign-in. See *Web UI* in
  `docs/reference/configuration.md` (Task 20393).
- **A web page can no longer drive the hub.** Handlers decoded JSON whatever the
  `Content-Type` and nothing checked a request's origin, so a `text/plain` form
  on any page reached any mutating route (on an SSO hub from another port or a
  sibling subdomain; without sign-in, from anywhere). Every
  `POST`/`PUT`/`PATCH`/`DELETE` without `Authorization: Bearer` is now refused
  with 403 `CROSS_ORIGIN` unless `Sec-Fetch-Site` is `same-origin` or `none` or,
  from an older browser, the `Origin` is the hub's own (the scheme and host
  addressed, `ui.external_url`, the SSO callback's, `ui.allowed_origins`).
  Bodies must be `application/json` (multipart for uploads), else 415
  `UNSUPPORTED_MEDIA_TYPE`. The hub sends no CORS headers: it answered every
  loopback `Origin`, so any page on localhost could read a hub without sign-in.
  Refusals are counted (`cloop_cross_origin_refusals_total`) and audited as
  `request.origin_refused` (Task 20394).
- **DNS rebinding is refused on a hub without sign-in.** An attacker's name
  re-pointed at 127.0.0.1 was same-origin with a loopback hub, so its page could
  drive every API, down to queueing agent runs. Such a hub now answers only to
  `localhost`, `*.localhost`, IP addresses, `ui.external_url`'s host, its
  cluster's advertise hosts and the new `ui.allowed_hosts`; any other `Host`
  gets 421 `MISDIRECTED_REQUEST`, audited as `request.host_refused`
  (Task 20394).
- **WebSocket origins are matched exactly.** The dashboard socket and the
  executor-agent endpoint admitted every loopback origin and every port of the
  hub's host; they now require the scheme, host and port of one of the hub's own
  origins. A schemeless `ui.allowed_origins` or `ui.allowed_ws_origins` entry
  means https (Task 20394).
- **`X-Forwarded-*` are believed only from a trusted proxy.**
  `X-Forwarded-Proto` was believed from any peer once `ui.external_url` was
  https, and the sign-in lockout and rate limiter counted the leftmost
  `X-Forwarded-For` entry, which nginx passes through from the client, so anyone
  could reset their lockout per request. Only loopback and the new
  `ui.trusted_proxies` (CIDR list) are believed now, and `X-Forwarded-For` is
  read from the right; HSTS and `cookie_secure: auto` follow the configured
  https URLs, not the headers. A proxy on another host needs an entry there for
  `/install.sh` and the one-line installer; the Helm chart lists the private pod
  ranges by default (`config.trustedProxies`), the compose stack its network
  (Task 20394).
- **`cloop serve` no longer answers every origin with
  `Access-Control-Allow-Origin: *`.** Without a token — its default — any page
  on the Internet could read the plan and `POST /run/start`. CORS is now granted
  only to a server with a token, and the same origin, media-type and Host rules
  apply (Task 20394).
- **The dashboard's markup carries no code, and its policy runs no inline
  script.** A project's name — a directory name anyone with `project.write`
  chooses — was spliced into inline `onclick` handlers, so a project named
  `demo&quot;+(…)+&quot;` ran script with the session of whoever clicked it,
  hub admins included; the presence bar rendered identity-provider display
  names as markup, and task links accepted `javascript:` URLs. Every control
  is now a `data-action` read as data by one dispatcher, links work only
  over http(s), and every response's policy is `script-src 'self'` without
  `'unsafe-inline'`, with `base-uri 'none'`, `form-action 'self'` and
  `object-src 'none'`. Browsers report violations to the new public `POST
  /api/csp-report`, counted in `cloop_csp_violations_total`. See
  `docs/security/threat-model.md` (Task 20408).
- **An SSO hub without a role policy says it runs with RBAC off, and one click
  leaves that state.** With `ui.oidc` on and neither `role_mappings` nor
  `default_role` set (a hub with only `admin_emails`, say), every identity the
  issuer authenticates holds every permission but executor administration,
  uncounted by quotas. Settings pre-selected "none", so saving any field wrote
  `default_role: none`, locking out everyone without a mapping at the next
  restart. Now `cloop hub doctor` fails `rbac.enforced`, `cloop ui` warns,
  `/api/me` reports `rbac_enforced`, and Settings says RBAC is off and offers
  **Enforce deny-by-default** (`POST /api/config/oidc/enforce`, audited as
  `oidc.rbac.enforced`), which writes `default_role: none` and keeps every
  current admin. A `ui.oidc` save that switches RBAC on or off needs
  `confirm_rbac` (else 409 `rbac_change`), and the new
  `ui.oidc.require_rbac: true` (Helm `oidc.requireRBAC`) refuses to start in
  that state. Audit rows there no longer name every actor `local` (Task 20395).
- **A project's directory is confined, so a maintainer can no longer hand
  sandboxes the hub's own state.** `dir` on `POST /api/projects/new` (and
  `cloop remote init --dir`) passed only a text denylist: a maintainer could
  register an ancestor of the control plane, such as `/var/lib` in the
  image, which a strict hub then bind-mounted read-write into its sandboxes
  with `.cloop/hub.env` and every tenant's project, and `?delete_root=true`
  deleted whatever a project named. A project may no longer be at or above
  `ui.projects_root`, overlap the hub's own directory (except under a root
  placed inside it, as in the image), another hub's or another project, or
  sit inside a `.cloop` directory; without `executor.manage` it must be
  inside `ui.projects_root` (`403` otherwise). Creations claim their path
  first (migration 0068, additive). Registered projects that break the rule
  are flagged, refused at run with `409` `project_unconfined`, and fail
  `cloop hub doctor` (`projects.confinement`); `?delete_root=true` deletes
  only a directory the hub created. See *Which directory a project may be*
  in `docs/architecture/executors.md` (Task 20418).
- **A project's own files can no longer aim the hub at another project's
  state.** A workload could write `.cloop/active_session` or a stored
  working directory so that the hub's reads and saves on its behalf landed
  in another project's database or the control plane's. Both now resolve
  only inside the project's own directory (Task 20418).
- **Creating a project no longer wipes one that already exists.** `POST
  /api/projects/new` ran `cloop init`, which overwrites the plan, history and
  settings it finds, so anyone with `project.write` could reset another
  person's project — even one they could not see — by naming its directory. A
  directory that holds a project is now refused with 409 `CONFLICT` (Task
  20417).
- **The hub's worktree sweep no longer runs what a repository configures.**
  On a strict hub it ran `git` in repositories sandboxes write, with the
  hub's whole environment, no deadline, and the repository's own hooks,
  `core.fsmonitor` and filters. It now runs with those off, in a closed
  environment, under a deadline, and skips a `.git` that is a file or a link
  (Task 20418).
- **Removing a project closes the dashboards still attached to it.** Live
  streams are filed by path, so a socket left open on a removed project received
  whatever was registered at that path next, possibly another person's project
  (Task 20366).
- **Revoking a grant takes it back from the workloads already holding it.** A
  revoked grant was refused only at the next lease, and a running container or
  Pod kept it until it exited. Every hub member now takes a revoked grant back
  from each live lease carrying it — files wiped wherever they were staged, keys
  emptied in a Pod's lease Secret, git-proxy and kube-guard sessions closed, App
  tokens destroyed — leaving the lease's other grants. A container or Pod
  holding it in its environment is removed, as the Secrets panel's confirmation
  warns. `cloop secret revoke` (waiting up to `--wait`) and `cloop hub user
  offboard` print what each member took back; `DELETE /api/grants/{id}` returns
  each holder's outcome, and the new `GET /api/grants/{id}/holders` previews
  them. Agents before protocol v19 give back the whole lease. An assignment edit
  that only widens supersedes the grant (`broker_grants.superseded_by`,
  migration 0063, additive) and the running task keeps going; one that narrows
  or switches the credential revokes it (Task 20403).
- **A revocation outlives the hub process holding the lease.** When the member
  holding a run's lease had died, or a hub had restarted before the run's agent
  reconnected, `POST /api/leases/{id}/revoke` reached nothing, answered 404 and
  recorded nothing, and the process that then adopted the run took the lease
  over and restored its git-proxy and Kubernetes-monitor sessions. A revocation
  is now recorded first (migration 0069, additive): no process takes over or
  extends a revoked lease, the adopter takes the material back instead, and the
  request answers 202 listing the holders still `pending`. A member that sees
  another die wipes the `/dev/shm` lease directories it left. See *Revoking
  what a dead member held* in `docs/architecture/hub-cluster.md` (Task 20419).
- **No run goes unsupervised.** A dispatch whose executor session could not be
  recorded ran untracked, never failed over or adopted, and a member that died
  between starting a workload and recording its run left it running with nobody
  holding its lease. A dispatch is now recorded before its workload exists
  (migration 0069); one that cannot be recorded is refused with 503 and its
  workload stopped, and a dead member's unrecorded workload is stopped and its
  credentials taken back. An adopted container or Pod is claimed by one hub
  process, which wipes, revokes and refreshes its credential files as its
  dispatcher would have (Task 20419).
- **A run's secret lease outlives the hub process that issued it.** A hub
  restarted while a device ran a task, or a hub-cluster member that died, left
  the run's lease held by nobody: never extended, swept or released, missing
  from the Secrets panel, and the adopted run's output no longer scrubbed of
  its values. Leases are now recorded (migration 0057, additive), and the
  process that adopts the run takes the lease over, keeps it alive, releases
  it, and scrubs env-secret and personal-access-token values from the output
  again; a lease that lapsed or lost its grant meanwhile is taken back from the
  device instead (Task 20382).
- **Revoking a session or an API token closes the streams and sandbox
  terminals it opened.** Revocation, sign-out, expiry and offboarding left
  dashboard WebSockets and `/api/events` streams running, and a sandbox
  terminal re-checked by re-running its opening request, which without the
  session resolved to the static token's allow-all: a revoked session kept
  its shell. Each stream and terminal now re-checks the credential that
  opened it — at once when this hub or the hub bus reports it ended, and
  every 30 seconds otherwise — and closes with `1008` and a
  `credential_ended` message. `cloop hub session revoke`, `cloop hub token
  revoke` and `cloop hub user offboard` announce on the hub bus, so running
  hubs act within about a second (Task 20398).
- **The static admin token can be retired at runtime, on every hub member.**
  `--token`/`CLOOP_UI_TOKEN` bypasses RBAC and never expires; stopping a hub
  honouring it took a Secret edit and a restart of every member, and the
  streams and sandbox terminals it had opened stayed open. `cloop hub token
  static retire --reason …` (or Settings → Static admin token, `POST
  /api/static-token/retire`) records its fingerprint (migration 0064,
  additive); every member then refuses it with `401` `static_token_retired`
  within about a second (30 seconds on a `ui.cluster.exclusive` hub) and
  closes what it opened. A new `CLOOP_UI_TOKEN` value is admitted. `cloop
  hub token static status` shows its last use, and `cloop hub doctor` warns
  `ui.static_token` while one is accepted beside SSO with an enforced role
  policy. See *The static token leaked* in `docs/operations/runbook.md`
  (Task 20406).
- **A session that ends mid-request is granted nothing.** On a hub enforcing
  a role policy, a request whose session ended between authentication and
  authorization was treated as the static token's, with every permission
  (Task 20412).
- **Offboarding destroys what a departed user kept on the hub, not only what
  they could use.** `cloop hub user offboard` and **Secrets → Offboard a user**
  left a person's personal secrets (GitHub PATs, kubeconfigs) and every grant
  over them live for colleagues' projects to spend, their grant requests open,
  and their Claude Code login home, with a plaintext OAuth refresh token, on
  every hub member. The plan (`--dry-run`) now lists these under
  **Credentials**; the run revokes the grants, deletes the secrets, withdraws
  the requests, and logs out (except on a strict hub) and removes each Claude
  home, reporting what failed without undoing the severing. A deleted secret's
  sealed payload and wrapped key are overwritten before its row is deleted and
  the WAL checkpointed; a tombstone keeps its name (migration 0062, additive).
  The CLI needs no `CLOOP_SECRET_KEY`. `--keep-credentials` (*Legal hold* in the
  dashboard) keeps secrets and homes and still severs access. A shared project
  granted a destroyed or withdrawn credential is refused it by name
  (`credential_refused` journal event). New audit actions `user.offboard_grant`,
  `user.offboard_secret`, `user.offboard_request`, `user.offboard_claude` and
  `user.offboard_hold` (Task 20400).
- **On a hub with single sign-on a personal Claude credential is spent only
  on its owner's runs.** A token one member granted to a shared project was
  used by every member's runs; other users' leases now withhold it, each
  with a `secret.lease` denial (Task 20379).
- **The provider-call log no longer stores credentials a lease lent.**
  `provider_calls.response` was written before redaction, so a leased value
  a harness echoed — a `GITHUB_TOKEN`, a proxy URL — was kept verbatim
  (Task 20378).
- **One credential registry for every scanner; `cloop audit` sees the tokens
  GitHub issues now.** `cloop audit` missed `gho_`, `ghu_` and `ghr_` tokens and
  every installation token minted since September 2026, reporting a clean
  history over a real leak; browser telemetry stored GitHub tokens and Anthropic
  keys from page errors verbatim; the broker's audit-reason scrubber and the
  provider-call audit knew few shapes. All four now use the registry in
  `pkg/redact` (`docs/reference/credential-patterns.md`). `cloop audit` streams
  the history, now reading merges, moved and binary-marked files too, and also
  reports *Credentials in task artifacts*; its history finding is now
  *Credentials in git history* (Task 20368). A review before landing
  (Task 20369) also stopped `cloop audit` running programs a repository's config
  names (`gpg.program`, a partial clone's `upload-pack`) and cut broker audit
  reasons to 8 KiB.
- **A Kubernetes Pod's environment is no longer readable from the Pod
  object.** Every environment value — the harness's Claude login,
  `GITHUB_TOKEN`, an egress session's proxy URL — was a plain value in the
  Pod spec, visible to anyone with `get pods` in the workload namespace. It
  now travels in the run's `cloop-lease-<handle>` Secret through
  `secretKeyRef`, so every run with environment or files creates that
  Secret; preflight's RBAC remedy now names `patch` on `secrets` as the
  chart does (Task 20401).
- **The Kubernetes access monitor refuses writes that would mint a
  credential.** It judged verb, resource and namespace only, so a write
  grant could create a `kubernetes.io/service-account-token` Secret, run a
  workload as another ServiceAccount or call the TokenRequest API, and keep
  a cluster credential that bypasses the monitor and outlives every revoke.
  It now reads the body of every create, update and patch of Secrets,
  workloads and custom resources, and refuses token Secrets, workloads that
  name a `serviceAccountName` other than `default` or reach the node (host
  namespaces, privileged, `hostPath`), every RBAC and
  CertificateSigningRequest write, `serviceaccounts/token`,
  `pods/ephemeralcontainers`, and bodies it cannot read (protobuf, CBOR),
  each under its own `kubeguard.request_denied` reason. Charts that create
  their own ServiceAccount or RBAC must be installed by a cluster
  administrator. See `docs/architecture/kubernetes-access.md` (Tasks 20416,
  20420).
- **A kubeconfig grant is delivered only where its limits are enforced.**
  Without `executors.kube_guard` the broker delivered the minimised
  kubeconfig whatever the grant said, so "read-only, namespace `app`" gave
  the workload everything the kubeconfig's identity may do. On such a hub a
  grant naming `--namespaces` or fewer than all eight verbs — read-only, the
  default, included — is now refused: the run goes without it, its Activity
  tab shows `credential_refused`, and `cloop hub doctor` fails
  `kubeguard.enabled`. An administrator may accept the risk per grant with
  `cloop hub grant unguarded <grant-id> --reason …` or **Acknowledge
  unguarded** in the Secrets panel (`POST /api/grants/{id}/unguarded`,
  audited as `secret.unguarded_ack`; migration 0070, additive) (Task 20420).
- **No allowlist reaches a cloud metadata service by containing it.** An
  entry such as `169.254.0.0/16` opened `169.254.169.254` on its ports, and
  allowing `fc00::/7` or `100.64.0.0/10` opened AWS's IPv6
  (`fd00:ec2::254`) and Alibaba Cloud's (`100.100.100.200`) endpoints. One
  table of metadata services now feeds the packet filter, the egress broker
  and Kubernetes NetworkPolicies: a service is reached only through its own
  `/32` or `/128`, and an entry containing one is refused unless the list
  names it. `cloop ui` refuses to start on such an in-force
  `executors.container.egress_filter.allow_cidrs` or
  `executors.kubernetes.egress_filter.cidrs` entry, `cloop hub doctor` fails
  `firewall.metadata`, the firewall APIs answer 400, and rules stored
  earlier keep the service closed. See `docs/guides/firewall.md` (Task
  20397).
- **Reaching the git proxy's port no longer writes to the audit trail.**
  git's credential-less first request of every clone, fetch and push was a
  `gitproxy.rejected` row — half the proxy's rows, and anyone who could
  connect could add more. It is now counted in
  `cloop_gitproxy_anonymous_requests_total`, and every per-request row
  names the repository the request addressed, which allowlist-scoped
  sessions left empty (Task 20346).
- **Git interception fails closed in every process.** `cloop serve`, `cloop
  hub doctor` and the CLI, which do not run the git proxy, handed a Pod's
  workspace fetch the forge credential itself even with
  `executors.git_proxy` enabled; they now refuse to provision the workspace
  (Tasks 20347, 20349).
- **Hub-scope settings in a per-instance overlay now govern the hub.** `cloop ui
  --port N` merged `.cloop/config.ui-N.yaml` for `ui.*` only and read every
  other hub-scope key from `config.yaml`: an overlay's
  `executors.allow_host_process: false` still let the dashboard spawn harnesses
  on its host, its image allowlist admitted any image, and its
  `executors.git_proxy` started no proxy, so forge credentials went into
  sandboxes. `docs/reference/configuration.md` lists the hub-scope keys
  (Task 20364).
- **Settings saves no longer leak between dashboards.** On a hub with an
  overlay, saving CI federation or the dictation key rewrote the shared
  `config.yaml`, which the other dashboard then read. Saves now go to the
  overlay when one exists (`ui.ci`, `stt.groq_api_key`), leaving `config.yaml`
  untouched (Task 20364).
- **`cloop hub doctor --smoke` keeps git tokens out of its sandbox** when any
  hub sharing the directory runs the git proxy, including one enabled only in an
  overlay; a configuration it cannot read counts as enabled (Task 20364).
- **`cloop hub doctor --smoke` opens no operator credential for its
  sandbox.** It could lease operators' grants aimed at its executor beside
  its own throwaway; it now withholds every grant but its own (Task 20413).
- **A device never moves back to a build earlier on `main` than its own unless
  root on the device says so.** Two edge builds could not be ordered, so the
  installer's downgrade guard checked only the protocol, and an upgrade
  request's `force` waved even that through: a compromised hub or agent could
  have the root upgrade helper install an older signed build. Every edge build,
  and every release from v0.0.5 on, is now stamped with its sequence, its
  commit's first-parent position on `main` (`cloop version` prints it). The
  installer reads both binaries' sequences and refuses a staged build with a
  lower one, or with none when the installed build has one; only root's own
  `cloop executor agent install --upgrade --to <target> --force` (or `--from
  <binary> --force`) overrides it, never the hub's or the request's `force`. The
  hub never offers such a build, and `POST /api/executors/{id}/upgrade` refuses
  it with 409 even with `force`. `cloop hub doctor` warns (`executors.edge_lag`)
  about an edge device more than 20 sequences behind the hub's build. See
  *Rollback protection* in `docs/guides/edge-channel.md` (Task 20380).
- **A compromised edge agent can no longer pin hub memory through the work it
  returns.** Every handle accepted write-back chunks up to the hard 128 MiB
  ceiling whatever its dispatch asked for, kept accepting them after it
  finished or was collected, and revoking the device freed nothing: up to
  32 GiB per agent per hub process. Late frames are now refused before anything
  is allocated, a handle holds only what its dispatch asked for, and held work
  counts against `executors.remote.max_pinned_writeback_bytes` (256 MiB per
  executor) and `executors.remote.max_pinned_writeback_total_bytes` (1 GiB per
  hub process); a write-back that would cross either fails with the limit named
  on the run's journal. `cloop_writeback_pinned_bytes` reports the level (Task
  20399).
- **An operator's resource ceilings bind container workloads.** A disk ceiling
  (`executors.limits.max_disk`, an executor's Limits, `cloop hub limits set
  <project> --disk`) was never applied on a container executor, and a device
  running payloads in a container got none of its CPU, memory or process
  ceilings for a project that stated no resources. Both now apply: an unstated
  limit is given the ceiling and a larger one is lowered to it; where nothing
  can hold a disk ceiling, the project's journal says so on every dispatch
  (Task 20405).
- **Failover never moves a run onto an executor with an access list, nor an
  isolated run onto the hub's own host, and the stranded run gives up its
  credentials.** A replacement was placed by health alone, so it could land on
  an executor whose access list excluded the run's owner or, with host
  execution allowed, on the hub's host; and the stranded run kept its lease
  alive, and a device that came back resumed the workload beside its
  replacement. Now the stranded run's leases and egress session close when its
  node is declared lost, and a returning device whose agent speaks protocol v5
  or later is told to terminate it (Task 20396).
- **Executor failover is capped, and a task that takes nodes down is
  quarantined.** A workload that kills its node (a fork bomb, a memory hog, a
  kernel panic) was re-dispatched without limit, taking down every enrolled
  device in turn. `executors.failover.max_attempts` (default 2, `0` for none, at
  most 10; hub-scope) bounds it. Past the cap the session closes
  `failover_exhausted` and its tasks fail naming every lost node, audited as
  `executor.failover_exhausted`. A task two distinct executors went down under
  is quarantined (`task.quarantine`), shown in its details and by the new `cloop
  executor list --inventory`, and runs again only after an explicit reset
  (`task.quarantine_release`), not with `--retry-failed`. A failover with
  nowhere to go now returns the lost node's tasks to pending, as documented
  (Task 20391).
- **The Projects grid's Run button and a new project's auto-run meet the same
  admission gates as the Overview's Run**: the executor's access list and the
  tenant's daily budget and concurrency quota, which they skipped (Task 20391).
- **The threat model's residual-risk column matches the code again**, and a docs
  gate fails the build when `docs/security/*.md` cites a test that does not
  exist (Task 20391).
- **A failed audit append is recorded in the chain it was meant for.** An
  append that failed (the database locked, read-only or full) left no trace:
  the next append linked to the last that succeeded, and `cloop hub audit
  verify` reported an intact chain over a trail with holes. Every failure is
  now counted and reported on stderr. The next append that succeeds writes one
  `audit.gap` row (new audit action) saying how many events of which actions
  were lost, when and why. A process that dies owing one leaves it in
  `.cloop/audit-failures/` for the next hub to record. `cloop hub audit
  verify`, `cloop audit-log verify` and `cloop events verify` exit 3 for an
  intact chain holding gaps (`--allow-gaps` for 0). `cloop hub doctor`, the
  Audit tab and `cloop_audit_append_failures_total` show them. See *Audit
  chain verification* in `docs/operations/runbook.md` (Task 20404).
- **Deleting the newest audit rows is detected.** A chain cut short at its
  newest end still verifies. The cluster leader now records each chain's head
  every `audit.checkpoints.interval` (default `5m`) and at clean shutdown. Each
  record is sealed with HMAC-SHA256 under a key derived from
  `CLOOP_SECRET_KEY`. Records go to `audit.checkpoints.file`, which must lie
  outside every `.cloop/`, and by default also as a JSON line on stderr
  (`audit.checkpoints.stderr`). `cloop hub audit verify --checkpoints <file>`
  fails (exit 2) when a chain no longer holds a head a checkpoint recorded.
  `cloop hub doctor` reports whether checkpoints are written, signed, fresh and
  agree with the chain. See *Audit head checkpoints* in
  `docs/reference/configuration.md` (Task 20404).
- **An edited backup no longer restores.** `cloop db restore` trusted the
  SHA-256 in a backup's unprotected sidecar, and a missing sidecar passed
  silently. Sidecars are now sealed under a key derived from
  `CLOOP_SECRET_KEY`; a restore refuses a missing or mismatched one
  (`--skip-checksum` overrides) and one whose seal it cannot check, such as a
  0.0.4 backup's (`--allow-unsealed`) (Task 20410).
- **cloop is built with Go 1.26.9 and `golang.org/x/net` v0.60.0.** v0.0.4's
  Go 1.25.14, a line now out of support, carries eleven standard-library
  advisories reachable from the hub's HTTP server, TLS and templates
  (GO-2026-6599, -6600, -6603, -6605, -6607, -6608, -6610 to -6613 and -6617).
  `go.mod` now declares `go 1.26.0` and pins `toolchain go1.26.9` (Task 20396).
- **cloop builds with OpenTelemetry v1.45.0**, for GO-2026-6505 in the
  `otlptrace` exporter v1.44.0, which the hub's tracing reaches (Task 20359).

### Upgrading from 0.0.4

0.0.5 changes defaults and refuses configurations 0.0.4 ran with. Back up,
upgrade every hub process on a control plane together, then the edge devices,
and run 0.0.5's `cloop hub doctor` right after: it names most of what follows.

#### Before you upgrade

- **Back up: a rollback is a restore.** Migrations 0049–0070 are all additive,
  so a 0.0.4 binary still opens an upgraded database, but every save it makes
  clears the new task columns and review verdicts, and it ignores what it does
  not know: retired static tokens work again, SCIM-suspended grants and project
  memberships vanish, kubeconfig grants are delivered unenforced. Run 0.0.4's
  `cloop db backup` in the hub's directory and in each project's first, let
  0.0.4 `cloop run` processes finish, and roll back by stopping every hub,
  reinstalling 0.0.4 and running its `cloop db restore <backup> --force`
  (Tasks 20361, 20388).
- **Stop every 0.0.4 hub on a control plane before starting 0.0.5**: the new
  `cloop ui` refuses to start beside a live 0.0.4 hub. A second `cloop ui` in
  one directory now joins the first as a hub-cluster member;
  `ui.cluster.exclusive: true` keeps one process (Task 20354).
- **Review per-instance overlays**: hub-scope keys in
  `.cloop/config.ui-<port>.yaml` — `executors.*`, `sandbox.image_policy`,
  `retention`, `audit`, `backup`, `stt`, `github.token` — now govern that hub,
  where 0.0.4 read only `ui.*` there (Task 20364).
- **Pause the fleet auto-update policy** until 0.0.4 devices are upgraded by
  hand (see *Edge devices*): it asks them again every 15 minutes, and every
  attempt fails on the device (Task 20376).
- **Building from source needs Go 1.26** (`go 1.26.0`, toolchain go1.26.9)
  (Task 20396).

#### Reaching the hub

- **A hub without sign-in binds `127.0.0.1`**: browsers and agents on other
  machines lose it. Give it `ui.oidc` or `CLOOP_UI_TOKEN`, tunnel over SSH, or
  name an address (`ui.listen`/`--listen`) and set
  `ui.allow_unauthenticated_network: true`, which warns at every start. `cloop
  serve` without a token binds `127.0.0.1` too (Task 20393).
- **The image refuses to start without sign-in**: its command now passes
  `--listen 0.0.0.0`. Set `CLOOP_UI_TOKEN` or `ui.oidc` (a Helm release on
  `secrets.existingSecret` too, which otherwise crash-loops). A custom command
  without `--listen` binds the container's own loopback (Task 20393).
- **A proxy on another host must be in `ui.trusted_proxies`**: `X-Forwarded-*`
  is believed only from loopback and that CIDR list, so otherwise `/install.sh`
  answers 403 and every client shares the proxy's rate limit. The chart's new
  `config.trustedProxies` lists the private ranges, but `helm upgrade
  --reuse-values` from chart 0.1.0 renders without it: pass it, or use
  `--reset-then-reuse-values`; a copied compose config needs the eval stack's
  entry (Task 20394).
- **Browser-facing rules are strict now** (Task 20394):
  - a state-changing request without `Authorization: Bearer` from another
    origin gets 403 `CROSS_ORIGIN`, and every request body must be
    `application/json` (415 otherwise) — scripts using `curl -d` need the
    header;
  - the hub sends no CORS headers, so a front end served from another origin
    must call the API server-side with a token;
  - `ui.allowed_origins` and `ui.allowed_ws_origins` entries are exact origins
    (scheme, host, port; no scheme means https);
  - a hub without sign-in answers only `localhost`, IP addresses,
    `ui.external_url`'s host and `ui.allowed_hosts` (421 otherwise), agents
    dialing it by name included.
- **The dashboard runs no inline script**: a proxy that injects a `<script>` is
  blocked. `POST /api/csp-report`, `/auth/sign-in.js` and `/assets/*` are
  served before authentication; a path allowlist must pass them (Task 20408).
- **An SSO hub without a role policy is reported as running with RBAC off**:
  nobody's access changes, but `cloop hub doctor` fails `rbac.enforced` and a
  settings save that would switch RBAC needs `confirm_rbac`. Use Settings →
  Single sign-on → **Enforce deny-by-default**, then `ui.oidc.require_rbac:
  true` (Task 20395).
- **Terminal sign-in is on wherever SSO is** (`/api/device/*`, `/device`);
  `ui.oidc.device_login: false` turns it off (Task 20412). **Browser telemetry
  is off** unless `ui.telemetry.enabled: true` or Settings → Telemetry turns
  it on (Task 20311).

#### Projects and runs

- **Projects whose directory breaks the confinement rule stop running** with
  409 `project_unconfined`: one at or above `ui.projects_root`, overlapping the
  hub's own directory, another hub's or another project, inside a `.cloop`
  directory, or a home or system tree. Run `cloop hub doctor`
  (`projects.confinement`) and move or remove each one. Without
  `executor.manage`, projects are created only inside `ui.projects_root` (403);
  creating one where a project exists answers 409; "Remove with directory"
  refuses projects created before the upgrade — remove the project, then its
  directory by hand (Tasks 20417, 20418).
- **Claude runs on isolating executors need a leased credential**: until the
  Overview's **Claude credential** card grants an env secret with
  `CLAUDE_CODE_OAUTH_TOKEN` or `ANTHROPIC_API_KEY`, or the executor is listed in
  `executors.harness_credential_exempt`, they are refused with 409
  `harness_credential_missing` (Task 20379).
- **Runs pause `disk_low` below 1 GiB free** on the volume of `.cloop` or the
  working tree (`orchestrator.min_free_disk_mb`; `0` turns it off), and each
  project keeps a 16 MiB `.cloop/reserve` (Task 20381). `cloop run` exits 74,
  paused `state_not_persisted`, when its database refuses a write (Task 20362).
- **A damaged `depends_on`, `on_success` or `on_failure` stops a project's loads
  and saves**, and migration 0054 stops startup if `plan_tasks` already has one
  of its columns in another shape; *A task row that will not load* in
  `docs/operations/runbook.md` repairs both (Task 20361).
- **Failover is narrower**: at most `executors.failover.max_attempts` (2) moves,
  never onto an executor with an access list or, for an isolated run, the hub's
  host; a run nothing replaces pauses `executor_lost`, and a task that took two
  executors down is quarantined until reset (Tasks 20391, 20396).
- **Restart each run started by 0.0.4 once** so it can adopt later builds;
  until then `cloop hub doctor` warns `runs.build_lag` (Task 20389).

#### Credentials, Kubernetes and the network

- **Constrained kubeconfig grants need the Kubernetes monitor**: without
  `executors.kube_guard`, a grant naming namespaces or fewer than all eight
  verbs (the read-only default included) is no longer delivered. Enable it
  (`{enabled: true, tls: auto}`; Helm `executor.kubeGuard.enabled` with
  `executor.monitorTLS.auto`), or accept each grant with `cloop hub grant
  unguarded <grant-id> --reason …` (Task 20420). The monitor also refuses
  RBAC, CertificateSigningRequest, token-Secret and other-ServiceAccount
  writes and unreadable bodies: install such charts as a cluster
  administrator (Tasks 20416, 20420).
- **Kubernetes executors**: a hand-written Role needs `secrets` `create`,
  `patch` and `delete` (every run now has a lease Secret), and a pinned
  `executors.kubernetes.image` must carry this release's cloop, or Pods fail
  with `unknown flag: --seed`; the hub's copy of the project now supersedes a
  `.cloop/` committed to the repository (Tasks 20401, 20402).
- **`executors.egress.enabled` now starts the egress proxy**, on an ephemeral
  loopback port by default: give containers a `listen_addr` such as
  `0.0.0.0:8899` and Pods and devices an IP `advertise_addr`, and name
  `api.anthropic.com` in egress grants (Task 20378).
- **`cloop ui` refuses to start on a firewall allowlist that contains a cloud
  metadata service** without naming it — `169.254.0.0/16`, `100.64.0.0/10`
  (Alibaba Cloud) or `fd00::/8` (AWS, GCP) — in an enabled container or
  Kubernetes `egress_filter`. Run `cloop hub doctor` (`firewall.metadata`) and
  narrow the range or list the service's own `/32` (Task 20397). An egress
  filter under rootless podman is refused (Task 20345).
- **`tls: auto` needs `CLOOP_SECRET_KEY` and agents at protocol v21**: upgrade
  devices before enabling it (Task 20409). `cloop serve` refuses git
  workspaces while `executors.git_proxy` is on (Tasks 20347, 20349).
- **Ceilings bind container runs**: `executors.limits.max_disk`, executor
  Limits and `--disk` now refuse and stop container runs, and container-mode
  devices get their CPU, memory and process ceilings; work a device returns is
  held to `executors.remote.max_pinned_writeback_bytes` (256 MiB) and
  `max_pinned_writeback_total_bytes` (1 GiB) (Tasks 20399, 20405).
- **Run every hub member on this build before enabling SCIM**: an older member
  would lease a grant SCIM suspended (Task 20415).

#### Helm and containers

- **Chart 0.1.0 → 0.4.1.** Upgrade at `replicaCount: 1`; more replicas need
  persistence and are pinned to the volume's node (Task 20354). Projects in
  `/var/lib/cloop/.cloop` are now refused: move them to
  `/var/lib/cloop/projects`, which the chart mounts as the projects root (Task
  20418). New values (`executor.gitProxy`, `executor.kubeGuard`,
  `executor.monitorTLS`, `extraCACerts`, `oidc.requireRBAC`, `strategy`) are
  off by default (Tasks 20385, 20409).
- **Feature runs on a container executor need git and this release's cloop in
  the sandbox image**; Kubernetes executors cannot run features (Task 20367).
- **Firewall rule sets refuse runs nothing can filter**: on Kubernetes set
  `executors.kubernetes.network_policy_enforced: true` or run `cloop hub doctor
  --probe-network-policy` (Task 20363).

#### Edge devices

- **A device on 0.0.4 speaks protocol v13; 0.0.5 speaks v21 and still runs its
  ordinary work.** What needs a newer agent is refused or degraded: virtual
  executors with a firewall or devices (v14), firewall rules stored in the hub
  (v15), features (v16), GitHub App token refresh (v17: tokens lapse an hour
  after dispatch), the egress proxy route (v18), revoking one grant without the
  whole lease (v19), disk limits (v20) and git-proxy workloads under `tls: auto`
  (v21) (Tasks 20345, 20363, 20367, 20375, 20378, 20403, 20405, 20409).
- **Upgrade 0.0.4 devices on the device: the Upgrade button cannot.** A 0.0.4
  agent accepts the hub's request and then fails it in its journal: the root
  helper that carries upgrades out ships in 0.0.5. On each device, as root, with
  `cosign` on `PATH`: `cloop upgrade` (0.0.4's own command fetches 0.0.5 and
  verifies its signature), then `cloop executor agent install --upgrade
  --remote-upgrade --packet-filter`, which restarts the agent on 0.0.5,
  installs the helper and grants what sandbox firewalls need — a plain
  `--upgrade` changes no unit file. From then on the Upgrade button and
  auto-update work, rollback protection covers the device, and `cloop hub
  doctor` (`executors.rollback_protection`) and its card stop warning (Tasks
  20352, 20376, 20380, 20421).
- **Enroll new devices with a freshly minted command.** The installer refuses a
  cloop older than the hub's protocol — downloaded, already on the device, or
  `CLOOP_BIN` — so re-enrolling a 0.0.4 device needs `cloop upgrade` first; on a
  hub running a published build of `main` the command installs that build with
  `--channel edge` (Task 20421).
- **The hub can never roll a 0.0.5 device back**: its installer refuses a build
  earlier on `main`, or one carrying no place on it — 0.0.4 included, and a
  binary built by hand without the stamp the hub's advice now names. Only root
  on the device can: `sudo cloop executor agent install --upgrade --to v0.0.4
  --force` (Tasks 20380, 20421).
- **Workloads waiting for a granted host interface should poll `IFF_UP`** in
  `/sys/class/net/<name>/flags` rather than wait for its name (Task 20349).

#### Operations, CLI and API

- **`cloop hub doctor` fails on hubs 0.0.4 passed** — `rbac.enforced`,
  `ui.exposure`, `firewall.metadata`, `projects.confinement`,
  `kubeguard.enabled`, `storage.free_space`, `config.repaired` — and warns on
  more (`secret_key.escrow`, `ui.static_token`, `runs.build_lag`,
  `executors.rollback_protection`), each with its remedy; a bare run diagnoses
  port 8080. A pipeline gated on its exit status turns red until they are fixed
  (Tasks 20381, 20387, 20389, 20393, 20395, 20397, 20406, 20410, 20418, 20420,
  20421).
- **Restores and audits**: `cloop db restore` needs `--reason` and every hub
  stopped, and a 0.0.4 backup `--allow-unsealed`; try `--check` first (Task
  20410). `cloop hub audit verify`, `cloop audit-log verify` and `cloop events
  verify` exit 3 on recorded `audit.gap` rows (`--allow-gaps`), and the hub
  prints audit head checkpoints to stderr every five minutes until
  `audit.checkpoints.file` names a file outside `.cloop/` (Task 20404).
- **Scripts may meet**: `GET /api/event-history` no longer returns `total`
  (page with `before=`; Task 20384); `POST /api/leases/{id}/revoke` can answer
  202 with `pending` holders (Task 20419); a dispatch that cannot be recorded
  answers 503 (Task 20419); several refusals that answered 500 are now 409
  with a code (Tasks 20364, 20379, 20417, 20418); `cloop hub quota set` and
  `cloop db maintain` refuse while a hub serves (Task 20354); `cloop migrate
  --from-version` is ignored (Task 20374). Some broken configuration now fails
  at load, naming the field (Task 20387).
- **Copy the CI workflow again** if you took it from Settings → CI/CD
  pipelines or `docs/guides/ci-pipelines.md`: with current Claude Code the old
  one fails with the relay's 403 (Task 20353).

### Added

- **Several `cloop ui` processes serve one control plane as a hub cluster.**
  A second hub on the same `state.db` refused to start; now every `cloop ui`
  joins the control plane as a member, and members behind a load balancer need
  no stickiness. A request only one member can answer — a Stop for a run it
  streams, a login callback, an edge agent's traffic — is forwarded to it over
  an HMAC-signed peer channel and authenticated again there; live events reach
  every member's dashboards; an elected leader runs retention, backups and the
  sweeps; a dead member's runs are adopted without restarting their harness,
  and SIGTERM hands them over. Members must share one kernel (one machine or
  node) and one `$HOME/.cloop/projects.json`, and reach each other at
  `--advertise-url`, `CLOOP_CLUSTER_ADVERTISE_URL`,
  `CLOOP_CLUSTER_ADVERTISE_HOST` or `ui.cluster.advertise_url` (default
  `http://127.0.0.1:<port>`); `ui.cluster.exclusive: true` keeps the
  single-process rule. `cloop hub cluster status` and `GET /api/cluster` show
  the members and the leader. The Helm chart allows `replicaCount` above 1,
  pinned to the volume's node (migration 0052, additive). See
  `docs/architecture/hub-cluster.md` (Task 20354).
- **`cloop login`: a terminal signs in to an SSO hub with a session of its
  own.** A terminal could get no credential from an SSO hub: API tokens need
  `token.admin`, and the session cookie never leaves the browser. `cloop
  login <hub>` runs the RFC 8628 device grant — a signed-in browser approves
  the code at `/device` — and the terminal gets a CLI session that expires
  and idles out (`ui.oidc.cli_session_ttl_hours`,
  `cli_idle_timeout_hours`), re-checks its claims, and is listed and revoked
  like a browser's; approving needs a sign-in newer than
  `ui.oidc.device_approval_max_age_minutes` (120). `cloop logout`, `cloop
  whoami` and `cloop remote projects|tasks|add|run|stop|logs` come with it,
  and `cloop task attach` uses the stored session. On wherever SSO is;
  `ui.oidc.device_login: false` turns it off (migration 0066, additive). See
  `docs/getting-started/terminal.md` (Task 20412).
- **SCIM 2.0 provisioning: an account the identity provider disables is
  suspended on the hub in one request, without an administrator.**
  Disabling a person at the identity provider ended nothing the hub had
  issued until someone ran `cloop hub user offboard`. Entra ID or Okta can
  now provision the hub at `/scim/v2` (with `ui.oidc` enabled), using a
  `cloop_scim_…` credential from Settings → Provisioning (SCIM) or `cloop hub
  scim credential create`. `active: false` writes a deny binding, ends the
  person's sessions, API tokens and glasses links, suspends grants over their
  personal secrets, releases their leases and stops their tasks; `active:
  true` lifts the deny and the suspension, and what ended stays ended. A
  `DELETE`, or `ui.oidc.scim.offboard_after_days` of deactivation, offboards
  fully, honouring legal holds (`cloop hub user hold`).
  `ui.oidc.scim.match_claim` picks the claim users are matched on, and
  provisioned groups become the `scim_group` claim kind for role bindings
  (migration 0067, additive). See `docs/guides/scim-provisioning.md` (Task
  20415).
- **SSO sessions renew from the browser when the hub cannot.** A hub that
  keeps no refresh token (no `CLOOP_SECRET_KEY`, or a provider that issues
  none) refused every action above operator once a session's claims passed
  `max_claim_age_minutes`, until the user signed out. The dashboard now
  re-asserts them through a hidden `prompt=none` frame at the new `GET
  /auth/renew` before they go stale, and once more when a call is refused as
  renewable; when the provider needs the user, a banner offers a sign-in
  that returns to the same view. A renewal sets no cookie and never extends
  the session. See *Silent renewal from the browser* in
  `docs/security/model.md` (Task 20359).
- **Project sharing.** On a hub with single sign-on, a project's maintainer adds
  named people at a role no higher than their own, from the Overview's
  **Members** card or `cloop project members add`. A membership only adds
  access, also on a hub whose `default_role` is `none`, and extends to the
  member's glasses link, tokens minted for them and the project's features;
  removals apply on every hub within seconds and close the member's open
  dashboard; members can leave. API `/api/projects/{idx}/members`, permission
  `project.share`; audit actions `project.member.grant`, `.change`, `.revoke`,
  `.leave`. See *Project members* in `docs/security/model.md` (Task 20366).
- **`cloop remote init` creates a hub project from a local checkout.** In a
  git checkout it creates the project on the hub — by name under the new
  `ui.projects_root` (default `projects/` in the hub's home,
  `/var/lib/cloop/projects` in the packaged image) — binds `--executor`,
  grants the GitHub origin through a GitHub App or the caller's
  git-proxy-guarded token (`--access write`, `--branch`), requests from an
  approver what the caller may not grant, naming who can approve it, settles
  the Claude credential, prints the dashboard link and with `--run` starts it.
  Beside it: `cloop remote executors`, `repos`, `grants` and `features`, each
  with `--json`. `POST /api/projects/new` takes a `name` instead of a `dir`, and
  grant requests list their `approvers`. See
  `docs/getting-started/terminal.md` (Task 20417).
- **Disaster recovery: the sealing key can be escrowed, and a restore checks
  the key before it swaps anything.** Losing `.cloop/hub.env` lost every
  sealed secret, and `cloop db restore` swapped in a backup the hub's key
  could not open, leaving a hub that would not start. `cloop hub key escrow
  export|verify|import` keeps `CLOOP_SECRET_KEY` sealed under a passphrase,
  and `cloop hub doctor` warns `secret_key.escrow` until it is. `cloop db
  restore` now runs a read-only preflight first (`--check` runs it alone),
  including whether the key opens the backup's sealing keys, which only
  `--accept-secret-loss` overrides; requires `--reason`; is refused while a
  hub serves the database; and records itself as `audit.restored` and in
  the audit checkpoints, which then accept the restore (exit code 3: restored
  but not fully recorded). See the runbook's *Disaster recovery drill* (Task
  20410).
- **The edge channel: devices can follow the hub's own build, signed by CI.**
  After CI passes on a push to `main`, `edge.yml` builds the commit for every
  release platform (stamped `dev+g<short sha>`) and signs the archives and a
  manifest with Sigstore keyless signing, as assets of an `edge` prerelease that
  is never latest and keeps the newest 30 commits. Edge builds are trusted by
  their own pin, `edge.yml@refs/heads/main`, only for an `edge:<commit>` target;
  the release pin refuses them. A device opts in locally with `sudo cloop
  executor agent install --upgrade --channel edge` (`20-update-channel.conf`,
  which upgrades keep and the hub cannot change); the Upgrade dialog and
  auto-update then offer **this hub's build** once CI has published it, and only
  if it does not lower the device's protocol, else say why not. `install
  --upgrade --to <target>` fetches, verifies and installs a published build. See
  `docs/guides/edge-channel.md` (Task 20376).
- **Remote upgrade works on a hardened device.** The unprivileged agent cannot
  replace its root-owned binary, so an accepted Upgrade failed in the device's
  journal. A root helper (`cloop-executor-upgrade.path` and `.service`,
  installed by default and by `install --upgrade --remote-upgrade`) now carries
  out the request on the channel systemd gives the device, with the usual
  verification, backup, restart and rollback. A device without the helper, with
  its path unit inactive, or without cosign refuses before acknowledging, and
  the Upgrade dialog shows why (Task 20376).
- **`cloop hub doctor` and the Executors panel name every device rollback
  protection does not cover.** The doctor looked for a build without a sequence
  only on edge devices, though every release before this one carries none.
  `executors.rollback_protection` now warns about each device that follows
  releases on such a build, and the device's card in the Executors panel says
  the same (`rollback_note`), each with the way to cover it: the Upgrade button,
  or — for an agent from before the remote-upgrade helper — once on the device,
  as root, `cloop upgrade` and then `cloop executor agent install --upgrade
  --remote-upgrade` (Task 20421).
- **Virtual executors.** An enrolled device can carry named sub-executors, each
  with its own container engine, OCI runtime, image, network and **host
  devices**; projects bind to one like to any executor, and limits and the
  access list apply under its own ID — so one machine can offer a locked-down
  sandbox to everyone and its hardware security module to a few. Press
  **Virtual** on a device's card in the Executors tab to choose its USB devices
  from the device's inventory, and its network: **No network** (the default),
  **Firewalled** (a bridge of its own under an IP firewall with an allowlist
  and a denylist) or **Unfiltered**. The Settings tab lists every device's USB
  hardware. API: `/api/executors/{device}/virtuals`,
  `/api/executors/{id}/virtual`; audit action `executor.virtual`. See
  `docs/guides/virtual-executors.md` (Tasks 20345, 20356).
- **Executor protocol v14.** Agents report their USB inventory, whether they can
  install a packet filter, and their engine's OCI runtimes; a start frame can
  carry a virtual executor's firewall and devices, resolved against the device's
  live hardware at every dispatch (an unplugged device fails the start by name).
  USB devices are selected by identity, not `/dev/bus/usb` path (Task 20345).
- A denylist for the IP-layer egress filter (`netfilter.Input.DenyCIDRs`),
  compiled ahead of every allow and carried into Kubernetes NetworkPolicies as
  `except` ranges (Task 20345).
- **Devices and projects carry firewall rule sets, each inside the one
  above.** A sandbox's IP firewall came only from an executor's
  `egress_filter` or a virtual executor's own, with no ceiling per device and
  nothing a project's maintainers could narrow. An administrator now sets a
  device's rule set (the device's card → **Firewall**), the most any sandbox
  on it may reach, virtual executors included; a project's maintainers
  (`config.write`) may narrow it on the Overview's **Network Firewall** card.
  Containment is checked on save (409 `firewall_exceeds_bound`), at dispatch
  and in the driver, and tightening a device narrows what is saved under it.
  Devices apply rules from protocol **v15**, Kubernetes only where
  NetworkPolicy enforcement is proven or asserted; runs on the host-process
  executor, a host-mode device or a rootless engine are refused while rules
  apply. API: `/api/executors/{id}/firewall`, `/api/firewall`; audit actions
  `executor.firewall`, `project.firewall` (migration 0055, additive). See
  `docs/guides/firewall.md` (Task 20363).
- **The executor installer grants the agent what a sandbox firewall needs, and
  nothing the agent starts receives it.** A device's hardened unit allowed no
  capability and no netlink socket, so nft(8) could not install a firewall
  there. `cloop executor agent install` now adds `CAP_NET_ADMIN` and
  `AF_NETLINK` in a systemd drop-in, `10-packet-filter.conf`
  (`--packet-filter=false` withholds it); an installed device gets it with
  `--upgrade --packet-filter`, never from a plain `--upgrade`. Every cloop
  process clears its ambient and inheritable capabilities at startup, and only
  nft(8) is handed `CAP_NET_ADMIN` back — never a workload, git or a shell
  (Task 20352).
- **Features run on isolating executors.** A feature's worktree names its
  parent's `.git` by its path on the hub, so features ran only on the hub's
  host executor, and on a hub with `executors.allow_host_process: false` not
  at all. A feature now travels to the executor as its branch, in a git bundle
  capped by `executors.feature_bundle_mb` (default 32, at most 128): a
  container executor needs git and this release's cloop in its sandbox image,
  a remote agent protocol **v16** and git, and a Kubernetes executor or an
  older agent is refused with a 409. The run's commits come back vetted and
  fast-forward the feature's worktree only when it is clean and on its branch;
  otherwise they are kept on `cloop/returned/<slug>/<run>` and the feature
  shows a conflict. The hub opens its pull request. See
  `docs/guides/features.md` (Task 20367).
- **Container executors hold a workload to `resources.disk`.** The container
  driver refused any disk limit, so a project that set one could not run on a
  container executor at all. It now measures the workspace while the workload
  runs: a tree already over the limit is refused at the start (409
  `workspace_over_disk_limit`), and one that grows past it is stopped and its
  run paused with the new reason `disk_limit`, the task back to pending. This
  is sampling, not a quota, so keep `orchestrator.min_free_disk_mb` on. A
  device holds the limit in container mode from agent protocol **v20**. See
  *`resources.disk` and the workspace* in `docs/reference/sandbox.md` (Task
  20405).
- **A long-lived run moves to a newly deployed build at a task boundary, and
  the dashboard shows when a run is behind.** A deploy replaces the binary but
  not the runs it started, so a run in auto-evolve kept its build
  indefinitely. The Overview, `cloop status` and `cloop hub doctor`
  (`runs.build_lag`) now show a run's build and how far it lags the hub. A
  host-process run on Linux moves without stopping — once with **Adopt at next
  task boundary** (`POST /api/run/adopt-build`, audited `run.adopt_requested`)
  or always with the per-project **Follow New Builds** option (`cloop run
  --follow-builds`, off by default) — when the binary at its path is a newer
  sequence-stamped build embedding the database's schema: it re-executes in
  place, keeping its pid, live log and run claim (audited `run.reexecuted`); a
  refusal is journalled as `run_adoption` and the run carries on. See
  *Following new builds* in `docs/reference/configuration.md` (Task 20389).
- **GitHub App tokens outlive GitHub's hour.** The hub re-mints a `github_app`
  grant's installation token about ten minutes before it expires, at the first
  token's exact scope and only while the grant still authorises the lease, and
  destroys the old one once unused. The git proxy renews upstream itself;
  otherwise the lease keepalive rewrites the sandbox's `github-token` file in
  place, on an edge device via the new `secret_refresh` frame (agent protocol
  **v17**; an older device keeps its token, journaled) and on Kubernetes by
  patching the lease Secret (the chart's executor Role gains `patch` on
  `secrets`). A refresh GitHub or the broker refuses ends the grant's access
  like a revocation. Audit: `secret.renew` per re-mint, the new `lease.refresh`
  per delivery. See *Keeping the token past GitHub's hour* in
  `docs/guides/secrets.md` (Task 20375).
- **The git proxy and the Kubernetes monitor need no certificate: `tls:
  auto`.** Turning either on took a certificate every sandbox image already
  trusted, so most hubs ran neither and put forge and cluster credentials
  in sandboxes. With `executors.git_proxy.tls: auto` (and
  `executors.kube_guard.tls: auto`) the hub mints its own CA, sealed under
  `CLOOP_SECRET_KEY` and shared by every hub-cluster member (migration 0065,
  additive), and serves each monitor a short-lived certificate it renews
  itself. Sandboxes trust the CA for the proxy's URL only: host processes,
  containers and Pods receive it with the run, edge devices in the start
  frame (protocol **v21**; an older agent is refused a workload that would
  use the proxy), and the kube guard embeds it in the kubeconfigs it
  issues. Helm: `executor.monitorTLS.auto`. See
  `docs/git-interception-proxy.md` (Task 20409).
- **The Helm chart runs the git proxy and the Kubernetes monitor.** Neither
  could be enabled from `values.yaml`, and `config.extra` cannot add a
  second `executors:` block. Chart 0.3.0 adds `executor.gitProxy` and
  `executor.kubeGuard` (ports 8443 and 8444, off by default) and
  `executor.monitorTLS` (`auto` from chart 0.4.0, an existing TLS Secret,
  or a generated one), plus `extraCACerts` and `hostAliases`; workload Pods
  trust the CA for the proxy's URL only
  (`executors.kubernetes.git_ca_bundle`).
  `executors.kube_guard.audit_allowed` also audits forwarded requests. See
  `deploy/README.md` (Task 20385).
- **Share a cluster behind `kubelogin`, `aws eks get-token` or the GKE
  plugin: `cloop remote kube share`.** The hub will not run an exec
  credential plugin, which left such clusters with no supported path.
  `cloop remote kube share <name> --context <ctx> --namespaces a,b` runs the
  plugin on the developer's machine, creates a ServiceAccount bound to
  `view` (`edit` with `--access write`, which needs `--sa-namespace` outside
  the shared namespaces), mints a bounded token (`--ttl`, default 24h) and
  stores its kubeconfig on the hub, as a personal secret on a hub with
  single sign-on. With the Kubernetes monitor on, the hub renews the token
  at half its life; otherwise `cloop remote kube renew` does. `list` and
  `revoke` complete it, and revoke and renew touch only objects the hub
  recorded and the cluster confirms are the share's. The dashboard refuses
  an exec-plugin kubeconfig at upload (400), naming the command. See
  `docs/architecture/kubernetes-access.md` (Tasks 20416, 20420).
- **A device run keeps its credential guards when its hub restarts.** Its
  git proxy, Kubernetes monitor and egress sessions, its workspace's git
  session and its App-token refresh lived only in the hub process, so after
  a restart its next fetch, push or `kubectl` call got a 401. They are now
  recorded — a token hash, never a token (migration 0058, additive) — and
  the hub that adopts the run restores them, never wider than the grant and
  this hub's policy allow now. See `docs/architecture/git-proxy.md` (Tasks
  20383, 20390).
- **A CI job relaying through the hub survives a hub restart.** Its relay
  session lived only in the process that minted it, so a deploy left the
  job "Not logged in" and unable to federate again. Sessions are now
  recorded (migration 0060, additive) and restored by the next call, held to
  their rule as it stands now; editing or deleting the rule ends them (Task
  20390).
- **`executors.write_back: push` returns a device run's work as a branch.**
  The hub never asked a device for a push write-back, so the work stayed on
  the device. With this opt-in setting a successful run's changes are
  committed to a fresh `cloop/run-…` branch and pushed to the project's
  `origin`, through the git proxy when it runs, so the device never holds
  the forge credential (Task 20390).
- **The hub hosts the egress proxy, and each run gets its own session.**
  `executors.egress` was validated but never bound, so an egress grant gave
  a run nothing. `cloop ui` now binds `listen_addr` (each hub-cluster member
  its own; `cloop hub doctor` reports it as `egress.hosted`), and a run
  whose project holds an active egress grant gets `HTTPS_PROXY` for a
  session of its own, renewed while it runs and never past the grant. Pods
  and devices reach it at `advertise_addr`; behind a device firewall that
  takes protocol **v18**. A `.cloop/sandbox.yaml` naming a grant the hub
  cannot serve is refused with 409 `sandbox_egress_unavailable`. Claude
  Code sends its model API calls through the proxy too. See
  `docs/reference/configuration.md` (Task 20378).
- **Review gate.** A project can have a reviewer model, of any provider, check
  each task's changes before anything leaves the working copy. While a task
  runs, the agent's `git push` is held; when it reports done, the reviewer reads
  the diff of every repository the task touched. On approval cloop sends the
  held pushes at the reviewed commits and lets git-mode and worktree merges
  proceed for the approved tree only. On a request for changes, mode `fix` sends
  the findings back and reviews again, `block` fails the task, `advisory`
  records and publishes; in `fix` and `block` no verdict fails the task.
  Configure it on the Overview's **Review gate** card, with `cloop review gate`
  or `/api/options/review-gate`; see `docs/guides/review-gate.md` (Task 20357).
- **Done means committed.** An opt-in, per-project check: a task its agent calls
  done is accepted only once its changes are committed (with *pushed*, also on
  its branch's upstream). A turn that leaves this attempt's changes uncommitted
  or unpushed is handed back naming them, at most twice; then the task returns
  to `pending` as an `uncommitted_work` abort, its work left in the tree, and
  the run pauses at the consecutive-abort ceiling. Pre-existing changes and
  `.cloop/` are never blamed; a push the review gate holds counts as pending.
  Set it with the Overview's *Done = Committed* / *…and Pushed* badges, `cloop
  run --require-committed[=pushed]` or `cloop require-committed`. See
  `docs/guides/done-means-committed.md` (Task 20370).
- **Runs pause before a full disk can swallow their outcome.** A full disk
  used to show up as a failed write, often the one recording a task's outcome.
  Before every task attempt and evolve round, a run now measures the volumes
  holding `.cloop` and the working tree. Below `orchestrator.min_free_disk_mb`
  (default `1024`; `0` turns it off) it starts nothing and pauses with reason
  `disk_low`. It carries on by itself once every volume has the floor plus a
  tenth free. If an outcome write still meets a full disk, the run releases a
  16 MiB `.cloop/reserve` so that the write can land. `cloop hub doctor`
  reports `storage.free_space`, and `cloop_hub_disk_free_bytes{volume}` tracks
  free space. Admins set the floor in the Budget tab's **Disk & Retention**
  panel (`PUT /api/config/disk`, audit action `disk.floor.updated`). See
  *Disk space low* in `docs/operations/runbook.md` (Task 20381).
- **The 18 metric families the catalog declared but nothing recorded now carry
  samples.** They were scraped with no series, so an alert on one could never
  fire:
  - run starts, completions, failures and durations
    (`cloop_executor_task_*`);
  - `cloop_executors` and `cloop_executor_heartbeat_age_seconds_max`;
  - `cloop_secret_leases_live` and `cloop_secret_kek_rotation_*`;
  - sessions (`cloop_sessions_*`);
  - API-token checks (`cloop_apitoken_auth_*`);
  - the egress broker (`cloop_egress_*`).

  Gauges read from the shared database are exported by the cluster leader
  only. See `docs/operations/metrics.md` (Task 20377).
- **Settings → Telemetry.** An admin switches front-end telemetry on or off,
  optionally per front end (`ui.telemetry.sources`), and sees what is stored and
  for how long; switching off deletes nothing. API `GET`/`PUT
  /api/config/telemetry` (`user.manage`), audit action
  `telemetry.config.updated`; an overlay holds it if the hub has one
  (Task 20311).
- **Dictation goes where the caret is.** The Dictate buttons on the Tasks tab
  and in the task editor insert at the caret of the field you were in, replacing
  a selection, and a toast names the field; with no field focused they behave as
  before (Task 20309).
- **Multi-line task descriptions.** The Add Task description box takes several
  lines: Enter starts a new one, Ctrl+Enter (⌘+Enter on a Mac) adds the task
  (Task 20343).
- **CI gates on staticcheck, unused and ineffassign.** A **Lint** job runs
  golangci-lint v2.14.0 with staticcheck's SA checks, `unused` and `ineffassign`
  over the whole module; `make lint` runs the same. The 72 findings in the tree
  are fixed, among them TLS configs setting `PreferServerCipherSuites`, which Go
  has ignored since 1.17. errcheck stays off for now, as `CONTRIBUTING.md`
  explains (Task 20411).

### Changed

- **The installer a hub hands out never puts a device behind the hub.** It
  fetched `/releases/latest` whatever the hub ran, so a hub built from `main` at
  protocol v21 enrolled every new device with 0.0.4's v13 agent, which connected
  and was then refused virtual executors, stored firewall rules, features,
  secret refresh and the rest. `/install.sh` now refuses any cloop that speaks
  an older executor protocol than the hub — one it downloads, one already on
  the device, or `CLOOP_BIN` — naming both protocols and the remedy. When the
  hub runs a build of `main` that CI signed and published, the Executors panel's
  command ends in `install.sh --channel edge`: the script installs exactly that
  build, verified with its manifest against the edge workflow's identity, and
  puts the device on the edge channel, so the choice of channel stays in the
  command the device's operator runs. Otherwise it installs the latest release,
  and the panel says so when no signed build speaks the hub's protocol. See
  *Installing the agent as a service* in `docs/architecture/executors.md` (Task
  20421).
- **A sandboxed harness with no Claude credential is refused before it
  starts.** A `claudecode` or `anthropic` project on an isolating executor
  gets no Claude login from the hub, so a run without an env grant carrying
  one started and failed `auth_refused`. Runs, resumes, autoruns, plans,
  chat and reproductions are now refused with 409
  `harness_credential_missing` (or `harness_credential_expiring` within ten
  minutes of the lease's end). The Overview's **Claude credential** card
  grants one or stores a pasted token
  (`/api/projects/{idx}/harness-credential`); executors that bring their own
  are listed in `executors.harness_credential_exempt`. See
  `docs/guides/secrets.md` (Task 20379).
- **`cloop hub bootstrap` turns on the git proxy and the Kubernetes
  monitor.** A bootstrapped hub put forge and cluster credentials in
  sandboxes; it now enables both with `tls: auto` on ports 8443 and 8444
  (`--git-proxy-port`, `--kube-guard-port`) (Task 20409).
- **On Kubernetes the hub's project travels with the run, and supersedes a
  `.cloop/` committed to the repository.** The seed rides the run's lease
  Secret into the `workspace` init container, and the outcome comes back at
  the end of the Pod's log. A committed `.cloop/` is no longer what runs; the
  lease Secret must fit the API server's 1 MiB, or Start is refused (archive
  finished tasks with `cloop task archive`); and the harness image
  (`executors.kubernetes.image`) must carry this release's cloop, or the init
  container fails with `unknown flag: --seed`. See
  `docs/architecture/executors.md` (Task 20402).
- **The Helm chart gives a hub a projects root**: it mounts the state
  volume's `projects/` at `/var/lib/cloop/projects`, the default
  `ui.projects_root`, where the read-only image had nowhere to create a
  project. Chart 0.4.1 (Task 20418).
- **`cloop ui --port N` applies its executor policy with its overlay merged.**
  `executors.allow_host_process`, `min_agent_build` and `limits` were applied
  from `config.yaml` alone, so the shared value always won; an overlay's
  `allow_host_process: true` now relaxes a shared `false` for that hub alone
  (Task 20364).
- **Browser telemetry is off by default.** An unset `ui.telemetry.enabled` now
  means off, and the dashboard and the glasses page ask the hub (`GET
  /api/telemetry/config`, `/api/glasses/telemetry/config`) before sending
  anything. A config that says `enabled: true` keeps collecting (Task 20311).
- **The Event History panel is pushed its rows instead of re-reading them.**
  Every task or state update made the dashboard re-fetch `GET
  /api/event-history` in full, each request loading the whole project to return
  fifty rows (244 ms on a 50,000-step journal). A page is now two index reads
  (migration 0059, additive), about 3 ms at any journal size, paged with
  `before=`; new rows arrive as `history_append` messages. `offset=` still
  works; responses no longer carry `total`. Step output or event details over
  4 KB arrive cut and load whole when the row is opened (`?step=N`, `?event=N`)
  (Task 20384).
- **The Settings and admin tabs load the first time they are opened.** The
  Settings, Budget, Secrets, Audit, Quotas and Telemetry tabs and the executor
  dialogs were part of every first paint; they are now fetched on first open,
  with Retry if the fetch fails. First paint falls from 212 KB to 142 KB on
  the wire, and its ceiling (`eagerWireBudgetBytes`) from 213,000 B to
  144,000 B, so a new admin panel belongs in `pkg/ui/assets/js/deferred/`
  (Task 20386).
- **The stylesheet and the dashboard page ship without their comments**,
  about 7.6 KB of `app.css`'s 24 KB on the wire and 7 KB of the gzipped
  `index.html`; an asset its stripper cannot model is served as written
  (Tasks 20356, 20363).
- **The error boundary ships without its comments too.** `errboundary.js`, the
  one first-paint script still served as written, is stripped like the bundle:
  4.9 KB → 2.6 KB on the wire (Task 20360).
- **WebSockets run on `github.com/coder/websocket` v1.8.15**, the maintained
  successor of the deprecated `nhooyr.io/websocket`, for the dashboard, the
  hub-to-agent transport and sandbox attach. A socket closed because access was
  withdrawn now reaches the browser as 1008 with its reason, not 1006; an
  oversized frame still closes with 1009 (Task 20411).
- **CI runs `pkg/ui` in three shard jobs and fails any package that takes
  over 60% of its `-timeout`.** The workflow takes about 18 minutes instead
  of 27 to 34. The race step also starts its longest packages first, and
  tests copy a migrated database (`internal/statedbtest`) instead of
  building one. When the shards drift apart, refresh
  `scripts/test-durations/pkg-ui.txt` (see `CONTRIBUTING.md`). A real-browser
  layout sweep of every tab and dialog from 320 to 1280px also gates CI; a
  new tab or dialog needs an entry in it (Tasks 20372, 20407, 20414).
- **A security fix can no longer wait unnoticed for a release.** The scheduled
  *Released installer* workflow, which now also runs as soon as a release run
  finishes, fails "ship something" when an `[Unreleased]` Security entry in
  `CHANGELOG.md` is older than 14 days by `git blame`
  (`scripts/unreleased-security-age.py`). A release's notes longer than a
  GitHub release can hold are cut at a whole entry and link the rest, instead of
  failing the publish step after the artifacts are built (Task 20421).

### Fixed

- **Stopping a run returns its in-flight task to `pending`.** Stop, Ctrl+C
  and an expiring `--timeout` failed the task, left it `in_progress` or marked
  it `timed_out`, which stranded its dependants. The dashboard's Stop now also
  reaches runs on devices and in containers (Task 20348).
- **A run stops when a state write fails: it pauses as `state_not_persisted`
  and exits with status 74.** Runs ignored such failures and announced
  outcomes the database never held, so the next start ran the task again.
  `cloop status` shows the pause reason, and `cloop run --auto-evolve` now
  sticks (Task 20362).
- **Fourteen task fields survive a reload.** Every load dropped them: assignee,
  links, sprint and story points, risk and impact scores, retry budget, TDD
  verdicts and the `on_success`/`on_failure` branches, among others. A branched
  plan stopped branching (migration 0054, additive) (Task 20361).
- **A damaged `depends_on`, `on_success` or `on_failure` stops the project
  instead of releasing the task early.** It used to read as empty. Loads now
  fail and saves refuse, naming the task and column. See *A task row that will
  not load* in `docs/operations/runbook.md` (Task 20361).
- **Saves update rows in place, so a column a later release adds survives
  them.** They replaced whole rows and erased every column the binary did not
  know. A future column on `plan_tasks`, `quota_counters` or `ci_exchanges` is
  recorded `additive-columns`, which earlier builds refuse (Task 20388).
- **The database's write-ahead log stays bounded.** It never shrank after a
  burst of writes. Connections now trim it to 64 MiB, the leading hub
  truncates it, and `cloop hub doctor` warns on `statedb.wal`. See *The
  write-ahead log* in `docs/operations/runbook.md` (Task 20392).
- **A turn that ends waiting on its own background work is handed back, not
  recorded done.** Such turns were recorded done with their work uncommitted.
  The agent is now resumed at most twice; after that the task goes back to
  `pending` as an `unfinished_turn` abort (Task 20349).
- **Task edits survive a running orchestrator's saves, and database opens and
  writes wait out locks.** The run's stale copy overwrote dashboard and CLI
  edits. An open could fail with `enable WAL mode: database is locked`. A
  write failed with `SQLITE_BUSY_SNAPSHOT` when another handle committed first
  (Task 20349).
- **Recovery no longer resurrects a task cloop rejected.** A run that died after
  the review gate, `--verify`, `--script-verify`, abandoned background work or
  an unanswered clarification had failed a task was recovered from the agent's
  `TASK_DONE`, so its dependents ran on rejected work. Each decision is now
  written first to `.cloop/artifacts/<id>_verdict.json`, which every recovery
  path applies before the agent's signal; a task whose review had not finished
  runs again (Task 20365).
- **Multi-agent mode obeys the review gate.** `cloop run --multi-agent`'s
  architect, coder and reviewer passes pushed a gated project's work straight to
  the remote; each now runs as a single agent would (push hold, task directory,
  effort and thinking settings), without a hidden ten-minute limit when no step
  timeout is set (Task 20365).
- `--script-verify` verified nothing without a step timeout, the default: the
  script ran under an expired deadline and the error counted as a pass
  (Task 20365).
- A task whose harness reported "API Error: Can't reach the API server" was
  recorded as done; it is now a `network_unreachable` abort that pauses the run
  and names the cause (Task 20345).
- A run on a hub in strict mode with no isolating executor got `500` "no default
  executor configured"; it is now a `409` `host_execution_denied` naming the
  setting and what to configure (Task 20364).
- **Switching a run between sequential and parallel no longer restarts it**:
  under `--replan` it discarded the plan, under `--retry-failed` it reset
  failed tasks, and the `pre_plan` hook ran again (Task 20389).
- **A device run survives its hub restarting mid-run**: it is adopted when its
  agent reconnects and its result merged once, where a restart used to lose the
  result and close the session as failed (Task 20382).
- **A failed-over run is dispatched and followed as the project's run**, with a
  fresh lease and seed; when nothing replaces it the project pauses with the
  new reason `executor_lost` instead of showing "running" forever (Task 20396).
- **A Kubernetes run is seeded with its project and its outcome reaches the
  hub's plan**; a repository needed `.cloop/` committed, and tasks a Pod
  finished ran again at the next Start (Task 20402).
- **A hub-cluster member that heartbeats but no longer answers is treated as
  down**: its runs are adopted and forwards to it fail with 502 instead of
  hanging; a forward waits at most 6 minutes for headers (Task 20419).
- **A device run no longer settles without its changes** when its status is
  asked for as the harness exits: this release's agent reports it running
  until its final status is sent (Task 20354).
- **A run on a device reads as running while it runs, and as stopped once it
  is stopped.** The hub showed the previous run's outcome until the device
  returned its state. A late reply to Stop could leave the run "unknown"
  (Task 20349).
- **The Upgrade button no longer moves a device backwards, and "upgrade the
  agent" says how.** On a hub running an unreleased build, Upgrade offered the
  hub's own `dev+g…` version, which no device can download, and `latest`
  (v0.0.4, protocol v13) would have taken a v14 device backwards. The hub now
  resolves `latest` to a tag and refuses a target that is not a release (400) or
  would lower the device's protocol (409; `force` overrides), and the dialog
  offers a release that would not, else says why there is none. `cloop executor
  agent install --upgrade` likewise refuses an older-protocol binary unless
  `--force`. Every refusal of a device's protocol now names the protocol the
  device speaks, the one the hub needs, and the remedy for the hub's build:
  Upgrade to the hub's own release on a hub that is one; on one that is not,
  build cloop at the hub's commit and install it on the device with `sudo
  ./cloop executor agent install --upgrade --insecure-skip-verify`. See *Moving
  a device forward* in `docs/architecture/executors.md` (Task 20371).
- **The hub's advice to build an agent by hand stamps its place on `main`.** It
  named a plain `go build`, which carries no sequence, so a device whose build
  carries one refused it unless forced — and, forced, was left with nothing to
  order its next upgrade by. The advised command now stamps the commit and its
  first-parent count, as release builds do (Task 20421).
- **cloop's own git no longer leaves housekeeping running in the background.**
  Since git 2.47 a fetch ends by starting `git maintenance run --auto`
  detached; after a provisioning or write-back step that child escaped the
  step's supervision and kept its environment — the leased credential's header
  included — while it ran. cloop's git children now keep it in the foreground
  (`gc.autoDetach` and `maintenance.autoDetach` off) (Task 20421).
- **A host-mode device run's home is `.<dir>.home` beside its checkout**: for a
  project holding a grant it was the checkout, so Claude Code's `.claude/`
  (session transcripts) landed in the repository (Task 20371).
- **`cloop hub doctor --smoke` no longer fails the dispatch of executors that
  can write back** (remote agents with git, Kubernetes) (Task 20367).
- **Binding an executor in `POST /api/projects/new` applies its access list**
  (403 `executor_audience_denied`), as binding it later always did (Task
  20417).
- A project's `capabilities.egress: public` on an executor whose firewall allows
  only a private range was handed the whole public Internet; it is now refused,
  as a scope may only remove reach (Task 20345).
- Device passthrough is no longer advertised or attempted under gVisor or Kata;
  on gVisor every open of the node fails with `ENXIO`, though the
  enterprise-hosts guide claimed it worked (Task 20345).
- A filtered sandbox resolves through the resolvers its filter opened, named in
  its own `resolv.conf`: dropping private space also dropped the engine's
  default resolver (on a cloud VM usually in CGNAT space), and under gVisor
  Docker's `127.0.0.11` is unreachable, so DNS failed (Task 20345).
- An egress filter is refused under rootless podman, whose networks the host's
  packet filter cannot see: the ruleset loaded, matched nothing, and the sandbox
  ran unfiltered (Task 20345).
- Revoking a device deletes its virtual executors, each with an audit row
  (Task 20345).
- The Executors panel's sandbox chip showed every container-mode device's
  network as `none`, from a field the API never filled in (Task 20345).
- **A granted host interface comes up last, once it has its address; wait for
  `IFF_UP`.** A workload that waited for the interface's name could find it
  unaddressed and fail. See *The start-up window* in
  `docs/guides/enterprise-hosts.md` (Task 20349).
- **A hub's startup sweep leaves another executor's just-exited container to
  its owner.** The owner recorded the clean exit as a failed run (Task 20349).
- **cloop never signals a process group whose id has been reused.** That id
  could belong to another project's run (Task 20349).
- The executor **Limits** dialog no longer overwrites a value typed before the
  stored ceiling has loaded (Task 20405).
- **A project can hold more than one kubeconfig grant.** A second one was
  refused (`secret_files[N] repeats path …/kubeconfig`); they now merge into
  one kubeconfig with a context per grant, and a credential the hub cannot
  deliver shows on the run as `credential_refused` (Task 20413).
- **A project can hold more than one GitHub grant.** A second one was
  refused (`secret_files[N] repeats path …/github-token`) or overwrote the
  first; each now gets its own token and helper (Task 20349).
- **GitHub access lasts the whole run.** A run's secret lease lapsed after
  15 minutes and took its GitHub token, proxy sessions and App token with
  it; the hub now extends a live run's lease in place (Tasks 20347, 20349).
- **Pods, virtual executors and moved checkouts work behind the git
  proxy.** A Pod's fetch presented the wrong username and its credential
  helper was not executable, releasing a lease destroyed the App token a
  session still presented, a virtual executor's workspace was leased as its
  device, and toggling the proxy stranded device checkouts (Tasks 20347,
  20349).
- **Git workspaces work on Kubernetes.** Every fetch into a Pod's
  root-owned `/workspace` failed with git's "detected dubious ownership"
  (Task 20385).
- **A Kubernetes run whose lease Secret is gone fails and names it.** It
  waited in `CreateContainerConfigError`, which a hub restarting mid-fetch
  could cause (Task 20401).
- **Audit rows are no longer lost when two writers append at once.** An
  append that raced another connection failed with `SQLITE_BUSY_SNAPSHOT`
  and was dropped; it is now retried (Task 20346).
- **An internal-only container egress filter needs no `CAP_NET_ADMIN`.**
  Without it, every run under `egress_filter.internal: true` was refused
  (Task 20378).
- **A hub started with `--token` loads its dashboard.** Its `/assets/*`
  bundle required the token, so no control worked; assets are now public on
  every hub, and the Assistant's input no longer throws (Task 20408).
- **A lapsed SSO session signs in again and returns to the same view.** A
  mid-session `401` opened the token prompt, useless to SSO users; it now
  goes through `/auth/login?return=` (Task 20359).
- **`cloop hub doctor` judges with the hub's own code**, so a working SSO hub
  on `/auth/oidc` passes `oidc.redirect_uri`; a bare run diagnoses port 8080,
  and `--port 0` reads `config.yaml` alone (Task 20387).
- **An OIDC callback path the hub cannot serve is refused at startup**
  instead of panicking it, and egress and git-proxy advertise addresses with
  no host are caught when the configuration loads (Task 20387).
- **`cloop db restore` works on a fresh host**: it no longer demands
  `--force` for the empty database the CLI had just created, and sets aside
  a stale `-wal` left without its database (Task 20410).
- **Three defects every interactive CLI user met.** (1) On a terminal every
  command queried its background colour and waited up to five seconds for a
  reply no pty gives (scripts driving `docker`/`kubectl exec -t`, CI with a
  tty), so `cloop status` took 5 s instead of 0.03 s. Nothing asks now.
  (2) Every project created by current cloop printed "warning: .cloop schema is
  out of date — run 'cloop migrate'" on every interactive command. The check now
  reads the database's own migrations, warning only for a legacy `state.json`
  project or a pre-migration database; `cloop migrate` works through the
  database layer, completes and adopts databases its old conversion left failing
  at migration 0009 ("no such table: stuck_tasks"), and ignores
  `--from-version`. (3) `cloop config validate --fix` reset in-progress tasks to
  `pending` even under a live run; it now leaves a live run's plan alone and
  otherwise recovers tasks as the hub does, journalled and audited. Every cloop
  database handle now opens with `busy_timeout` on each pooled connection
  (taskqueue's `MarkDone` failed at once with `SQLITE_BUSY`) (Task 20374).
- **`cloop task effort-calibrate` asks the model it resolved.** Without
  `--model` the provider's built-in default answered instead of the configured
  model (Task 20411).
- **`CLOOP_SOAK_KEEP` keeps the soak root**, as `docs/operations/soak.md`
  documented: its hub state, project databases and logs stay in a directory the
  test log names (Task 20411).
- **The CI workflow in `docs/guides/ci-pipelines.md` works with current Claude
  Code** (`--model sonnet`) and fails at the step that broke (Task 20353).
- **An evolving run offers Stop, and the Tasks tab says it is evolving**
  instead of offering Start and saying "Not running" (Task 20358).
- **Budget's Save Global Limits and Save Project Limits save**; both threw
  and had never saved a limit (Task 20386).
- **The Secrets tab's dialogs show the hub's refusal** instead of success,
  and a hub without sign-on gets shared secrets by default (Task 20386).
- **Long names, paths and URLs wrap or truncate instead of widening the
  page**, on every tab and dialog from 320 to 1280px (Task 20407).
- **The header's tabs wrap instead of widening the page**, which scrolled
  sideways at every desktop width (Task 20351).
- **Selects look like the page's fields in both themes**, and keys typed
  into an open list no longer trigger the dashboard's shortcuts (Task 20355).
- The Kanban board renders after a project switch, and switching the theme
  on the Timeline tab no longer throws (Task 20407).
- The command palette's run and reset entries, Knowledge Base search, Provider
  Calls filters and the init form's provider list now work (Task 20386).
- **The documentation site publishes every docs change again**; `build.json`
  names its commit and `make docs-freshness` checks it (Task 20373).
- **Diagram labels on the documentation site are readable in both colour
  schemes** (Task 20350).

## [0.0.4] - 2026-09-27

The first release that ships 0.0.2's installer fix. 0.0.2 was tagged on
2026-09-17 to publish unversioned asset names and never reached GitHub
Releases: its publish step failed partway through the uploads, the tag stayed
behind with no release, and `releases/latest/download` kept serving 0.0.1's
versioned names — so every device the installer was pointed at still got a
`404`. 0.0.3, tagged to publish it, stopped earlier still: its binaries did not
build for 32-bit linux/arm. What 0.0.2 was cut for is released here for the
first time: unversioned `cloop_<os>_<arch>.tar.gz` assets that
`latest/download` resolves, each with the Sigstore bundle the installer and
`cloop upgrade` verify its provenance against (0.0.1 published none), linux/arm
builds, and a daily check that the published release still installs — see 0.0.2
in `CHANGELOG.md` for the detail.

### Added

- **Parallel features.** `cloop feature new` — and **+ New feature** on a
  project's Overview — starts a line of work in its own git worktree on branch
  `cloop/feature/<slug>`, with its own task list and its own auto-evolve,
  innovate and parallel settings. Features run at the same time as their project
  and as each other; the dashboard nests them under their project, and each is
  otherwise an ordinary project with its own run, tasks and options. When one is
  done, **Open pull request** (`cloop feature pr`) pushes its branch and opens a
  GitHub pull request into the branch it was cut from — or the hub does it by
  itself on completion when the feature asked for that. A feature runs on its
  project's executor with its project's grants and roles, by a mapping read from
  its path so that it fails closed. See `docs/guides/features.md`.

### Changed

- **The dashboard's script ships without its comments.** Whole-line `//`
  comments were over a third of its wire bytes; they are now stripped when the
  bundle is built, keeping every line number, by a lexer that refuses — and
  serves the source unchanged — whenever it cannot prove a line is a comment.
  First paint fell from 279 KB to 213 KB, the parallel-features UI included.
- **Stop, the running indicator and run re-entrancy treat a feature as its own
  project.** A run in `.cloop/features/<slug>` no longer marks its parent as
  running, and the parent's Stop no longer signals it.
- `cloop clean` refuses while the project has features unless `--force`, which
  removes them through git first; snapshots neither archive feature worktrees
  nor touch them on restore; disk-usage reports no longer count them.
- **`cloop watch` applies one batch of changes at a time.** Every debounce
  window used to start a batch of its own, so a burst of edits applied several
  at once: their state saves raced — one could put back a task another had just
  reset — `--auto-run` ran `cloop run --pm` concurrently with itself, and
  stopping the watcher waited for the whole backlog. Changes that arrive while
  a batch is applied now make up the next one, and nothing starts after Ctrl+C.

### Fixed

- **cloop builds for 32-bit ARM again.** A token ceiling of `1<<40` did not fit
  in an `int` on linux/arm, the armv7 build the installer serves to Raspberry
  Pi-class devices, so nothing since 2026-09-26 compiled there. CI now builds
  the release binary for every published platform on every push, so a tag is no
  longer the first build to try one.
- **A release publishes, or can be resumed.** The release job now creates the
  release as a draft, uploads one asset at a time with retries, and marks it
  latest only once every asset is there. 0.0.2 was lost to a single upload
  error from GitHub with all twelve uploads running at once.
- **A terminal on an edge device no longer loses a short command's output.**
  A command that printed and exited at once — `pwd`, `echo` — sent its output
  and its close back to back, and the hub closed the session before relaying
  the output, so `cloop task attach` showed an empty transcript. The device
  also reaped such a command twice, a data race, and could hold one of its
  terminal slots for a session that had already ended; an attach the device
  refused left a goroutine behind on the hub.
- **A workload stopped on reconnect reports how it ended.** When the control
  plane refuses to take a workload back after a reconnect, the device stops it
  — but it used to signal it before the new session was ready, so a workload
  that died promptly had nowhere to send its last output or its exit status.
- **An exit reported as the link drops is kept.** The device counted a
  workload's final status as delivered before writing it, so a status written
  to a closing session was lost, and the control plane later read a clean exit
  as a lost workload. It is now delivered on the next session.
- **A revocation is sent to a reconnecting device once.** One recorded as the
  device reconnected could be sent twice, and the reply to the first could be
  taken by the second, reporting a reachable device as unreachable.
- **Push-to-talk no longer sends a clip it meant to discard.** A tap too short
  to be speech is thrown away, but its recorder stopped asynchronously, and a
  press landing before it had — a second tap at once, or any press on a slow
  device — let the discarded clip upload after all, often transcribed as a
  hallucinated title. A release the page got to late could also stretch a tap
  past the minimum hold. Holds are now timed by the pointer events themselves,
  on the dashboard and the glasses link alike.
- **`cloop chaos suite` gives every fault its full window.** Windows were
  measured from when the suite was built, so the last faults ran with a
  fraction of theirs — the SQLite one with under half a second of its two —
  and a slow disk reported them degraded.

### Security

- **gRPC 1.83.2** for GO-2026-6348, heap exhaustion through fragmented HTTP/2
  DATA frames, which the hub's metrics collectors can reach. OpenTelemetry
  moves to 1.44.0 with it.

## [0.0.3] - 2026-09-27

_Tagged, never published as a binary release: the release build failed on
linux/arm before anything was uploaded. Its container images were published
(`ghcr.io/blechschmidt/cloop` and `cloop-harness` at `v0.0.3`). Its changes
were released in 0.0.4._

## [0.0.2] - 2026-09-17

_Tagged, never published: the release job failed while uploading. Its changes
were released in 0.0.4._

This release exists to publish the installer fix below, which was written
against 0.0.1 and then never shipped. The repository was corrected; no release
was cut; and so `releases/latest/download` kept resolving against the versioned
names 0.0.1 had published, and every device kept getting a `404`. The code
being right is not the same as the artifact being right — and from a device,
only the artifact is reachable.

### Added

- **A scheduled check that the published release still installs.** Every
  existing gate compares this repository against itself, which is why the
  0.0.1 breakage survived its own fix: `scripts/build-release.sh`,
  `pkg/upgrade.assetNameFor` and the generated script all agreed, and the
  release disagreed with all three. `.github/workflows/released-installer.yml`
  now runs the real installer against the real release on a timer, because a
  release that goes stale relative to the code produces no commit for a
  pull-request check to catch.

### Fixed

- **The executor bootstrap installer could never install anything.** Two
  defects on the same path, the first hiding the second. Release archives
  carried the version in their names (`cloop_0.0.1_linux_amd64.tar.gz`) while
  the script served at `GET /install.sh` fetched
  `releases/latest/download/cloop_linux_amd64.tar.gz` — a URL no release had
  ever published, so every device got a `404`. With that fixed the install
  still died at exit 127: progress messages went to stdout, which is the
  channel `find_or_fetch_cloop` returns the binary path on, so the path came
  back with a log line glued to the front of it and was executed as one word.
  Release assets are now unversioned — which is what makes `latest/download`
  resolve at all — and every diagnostic goes to stderr.

### Added

- **The installer verifies what it downloads.** The archive is checked against
  the release's `checksums.txt` before anything is unpacked, failing closed on
  a mismatch, an unreachable checksums file, or an artifact missing from it.
  It is unpacked as root onto a device about to be handed credentials, so
  authenticating only the transport was not enough. `CLOOP_BIN` still bypasses
  the download entirely.
- **`linux/arm` (armv7) release builds.** The installer already mapped
  `armv7l`/`armv7`/`armhf` onto an asset that was never built, so 32-bit
  Raspberry Pi-class devices — the fleet's most likely edge hardware — were
  told "download failed".

### Changed

- Release assets are named `cloop_<os>_<arch>.tar.gz` rather than
  `cloop_<version>_<os>_<arch>.tar.gz`. `cloop upgrade` reads both, so a
  v0.0.1 binary still upgrades forward; the version now lives in the binary
  (`cloop version`) instead of in the filename.

## [0.0.1] - 2026-09-12

First tagged release. Everything below already existed; what is new is that it
is now installable as a versioned binary rather than only from source.

### Added

- **Autonomous task loop.** `cloop init` turns a goal into a plan and
  `cloop run` executes it: decompose into tasks, run each against an AI
  provider, detect completion from the agent's own output, and — with
  `--auto-evolve` — discover follow-up work and keep going.
- **Multiple providers.** Anthropic, OpenAI (including OpenAI-compatible
  endpoints), Ollama for local models, and the Claude Code CLI. Selection is
  layered: `--provider` flag, then `.cloop/config.yaml`, then project state.
  Retries use exponential backoff with jitter behind a circuit breaker.
- **Isolated executors.** The hub never spawns a harness on the host unless
  explicitly configured to. Backends: local process, Docker/Podman containers,
  Kubernetes pods, Kata Containers VMs, and remote agents that enrol
  themselves outbound — so an edge device behind NAT needs no inbound
  reachability. Placement is capability-aware with liveness, cordon/drain and
  automatic failover.
- **Scoped secret brokering.** GitHub repositories and PATs, kubeconfigs, and
  the hub's own Internet connection are leased to executors with a TTL rather
  than copied in. Leases are revoked on the running executor rather than at
  task exit, payloads are envelope-encrypted with online key rotation, and
  material is wiped on exit and swept at startup.
- **Enterprise hub.** OIDC authentication with claim-based RBAC that is
  deny-by-default on every mutating endpoint, durable sessions with idle
  timeout and admin revocation, scoped API tokens for non-interactive access,
  per-identity quotas and admission control, a hash-chained audit trail with
  SIEM export, and a container image trust policy (registry allowlist, digest
  pinning, signature verification).
- **Web dashboard.** Multi-project oversight over a WebSocket event stream,
  with kanban, dependency graph, timeline, analytics, knowledge base, and
  panels for executors, secrets, grants and audit.
- **Packaging.** A distroless container image, a docker-compose evaluation
  stack that runs a real task through a remote executor, a Helm chart, and
  `cloop hub bootstrap` / `cloop hub doctor`.
- **Roughly 115 CLI commands** covering planning, analysis, forecasting,
  reporting and integration. `cloop --help` groups them; `cloop doctor`
  checks the environment.

### Known limitations

- **No Windows build.** The process-group supervision used to stop harnesses
  is POSIX-only, so releases carry linux and darwin binaries (amd64 and arm64)
  only. `cloop upgrade` already knows how to unpack a `cloop.exe`; the
  platform needs a port, not a packaging change.
- The version is `0.0.1` in the sense SemVer intends: interfaces are not yet
  stable, and upgrades between 0.0.x releases may require configuration
  changes.

[0.0.5]: https://github.com/blechschmidt/cloop/releases/tag/v0.0.5
[0.0.4]: https://github.com/blechschmidt/cloop/releases/tag/v0.0.4
[0.0.3]: https://github.com/blechschmidt/cloop/tree/v0.0.3
[0.0.2]: https://github.com/blechschmidt/cloop/tree/v0.0.2
[0.0.1]: https://github.com/blechschmidt/cloop/releases/tag/v0.0.1
