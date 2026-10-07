# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

While the major version is 0, the command-line surface, the configuration
schema and the hub's HTTP API may change in any release.

## [Unreleased]

### Added

- **The edge channel: devices can follow the hub's own build, signed by CI.**
  After CI passes on a push to `main`, the new `edge.yml` workflow builds that
  commit for every release platform — stamped `dev+g<short sha>` as the hub's
  deploy stamps it — and signs each archive and a manifest `{commit, version,
  protocol, archive hashes}` with Sigstore keyless signing. They are
  commit-named assets of one `edge` prerelease that is never latest, whose tag
  is never moved, and which keeps the newest 30 commits. Edge builds are trusted
  by a pin of their own, `edge.yml@refs/heads/main`, accepted only for an
  `edge:<commit>` target; the tag-only release pin is unchanged and refuses
  them. A device opts in on the device — `sudo cloop executor agent install
  --upgrade --channel edge` writes `20-update-channel.conf`, which upgrades keep
  and the hub cannot change — and then the Executors panel's Upgrade dialog and
  the auto-update policy offer it **this hub's build (`<short sha>`)** once CI has
  published it and only if its manifest's protocol does not lower the device's,
  saying plainly otherwise why not: the deploy built an unpushed commit, CI has
  not published it yet, or CI failed. `install --upgrade --to <target>` fetches
  and verifies a published build on the device (Task 20376).
- **Remote upgrade works on a hardened device.** The agent runs unprivileged
  and could never replace its own root-owned binary or restart itself, so the
  Upgrade button was accepted and then failed in the device's journal. A root
  helper (`cloop-executor-upgrade.path` and `.service`, installed by default and
  by `install --upgrade --remote-upgrade`) now carries out the request the agent
  files: it takes the device's channel from systemd, verifies the build, and
  installs it with the usual backup, restart and rollback. A device that cannot
  carry out an upgrade — no helper, a helper whose path unit is not active, or
  no cosign — refuses before acknowledging and says why; the dialog warns with
  what it said at hello and asks it again on Upgrade (Task 20376).

- **GitHub App tokens outlive GitHub's hour.** A run that still uses git more
  than an hour after dispatch keeps its GitHub access. The hub re-mints a
  `github_app` grant's installation token when about ten minutes of its hour
  are left — at exactly the scope of the first (same installation, same
  repositories by ID, same permissions, never wider than GitHub granted the
  first time), and only while the grant still authorises the lease — and
  destroys the token it replaced once nothing presents it. Under the git proxy
  the session renews the token it presents upstream from its own request path;
  without it the lease keepalive rewrites the sandbox's `github-token` file in
  place: on the hub's host, in a container's staged directory, on an edge
  device through the new `secret_refresh` frame (agent protocol **v17**), and on
  Kubernetes by patching the run's lease Secret (the chart's executor Role gains
  `patch` on `secrets`). A refresh the broker or GitHub refuses — the grant
  revoked or expired, the installation suspended, a repository removed from it —
  ends the grant's access as revocation does; a device too old for the frame is
  journaled instead of refused, and keeps the token it was given. Each re-mint
  is an allowed `secret.renew` row; each delivery to an executor a
  `lease.refresh` row (new audit action). See *Keeping the token past GitHub's
  hour* in `docs/guides/secrets.md`.

- **Done means committed.** An opt-in, per-project post-condition: a task
  whose agent says it is done is accepted only once the changes it made are
  committed — and, with *pushed*, on its branch's upstream. When a turn ends
  with this attempt's changes uncommitted (or its commits unpushed), the turn
  is handed back in the same conversation naming the paths and commits, at
  most twice; a task that still ends that way goes back to `pending` as an
  `uncommitted_work` abort with its work left in the tree, the next attempt is
  held to it, and the run pauses (reason `uncommitted_work`) at the
  consecutive-abort ceiling. What was already dirty when the task started,
  and `.cloop/`, are never blamed; a push the review gate holds counts as
  pending. Set it with the Overview's *Done = Committed* / *…and Pushed*
  badges, `cloop run --require-committed[=pushed]` or `cloop
  require-committed`; `cloop status` shows it. It travels to isolating
  executors with the project. See `docs/guides/done-means-committed.md`.
  The unfinished-turn detector also recognises the ending that stranded Task
  20368 ("the only thing still running is …, then commit and push"), re-checked
  against the project's 314-message ledger with no signalled turn matching.

- **Project sharing.** On a hub with single sign-on, a project's maintainer
  adds named people to it at a role — never above their own role there — from
  the Overview's **Members** card or `cloop project members add`. A membership
  only adds: someone who already holds more keeps it. A member sees the project
  in their list, on their glasses link and through tokens minted on their
  behalf, including on a hub whose `default_role` is `none`, and its features
  come with it. A removal takes effect on every hub within seconds and closes
  the member's open dashboard on the project; members can also leave. API:
  `/api/projects/{idx}/members`, permission `project.share` (maintainer and
  up); audit actions `project.member.grant`, `.change`, `.revoke` and `.leave`.
  Offboarding a user removes their memberships, and removing a project drops
  its roster. See *Project members* in `docs/security/model.md`.
- **Settings → Telemetry.** An admin switches front-end telemetry on and off
  from the dashboard, optionally for one front end only
  (`ui.telemetry.sources`), and sees what is already stored and for how long;
  switching off deletes nothing. API: `GET`/`PUT /api/config/telemetry`
  (`user.manage`); audit action `telemetry.config.updated`. On a hub with a
  per-instance overlay (`.cloop/config.ui-<port>.yaml`) the setting is read
  from and saved to that file.
- **Dictation goes where the caret is.** The Dictate buttons on the Tasks tab
  and in the task editor insert what you said at the caret of the text field
  you were in — the Add Task description, the task filter, the editor's Title —
  replacing a selection, and a toast names the field. With no field focused
  they do what they did before: append to the Add Task title, and in the editor
  ask whether to replace the description, add to it or edit it with AI.
- **Multi-line task descriptions.** The description box in the Tasks tab's Add
  Task form takes several lines: Enter starts a new one, and Ctrl+Enter
  (⌘+Enter on a Mac) adds the task. It was a one-line field that flattened a
  pasted brief into one run-on line.
- **Review gate.** A project can have a reviewer model — its own provider and
  model, free to differ from the ones doing the work — check each task's changes
  before anything leaves the working copy. While a task runs, the agent's `git
  push` is held (reported to it as "held by cloop's review gate" and recorded,
  through a `pushInsteadOf` rewrite in its environment only); when it reports
  the task done, the reviewer reads the diff of every repository the task
  touched, read-only. On approval cloop sends the held pushes itself, at the
  reviewed commits and never with a commit the reviewer did not see, and lets
  git-mode and worktree merges proceed only for the approved tree. On a request
  for changes, `fix` mode sends the findings back to the agent in its own
  conversation and reviews again, `block` fails the task, `advisory` records
  and publishes. A reviewer that gives no verdict fails the task closed.
  Configure it from the Overview's **Review gate** card or `cloop review gate`;
  the verdict shows in the task list, the task details and the event history.
  API: `/api/options/review-gate`. See `docs/guides/review-gate.md`.
- **Virtual executors.** An enrolled device can carry named sub-executors, each
  with its own container engine, OCI runtime and image, an **IP firewall with an
  allowlist and a denylist**, and the **host devices** its sandboxes are given.
  Projects bind to one like to any executor, and resource limits and the access
  list apply to it under its own ID — so one machine can offer a locked-down
  sandbox to everyone and one holding its hardware security module to the few
  people allowed near it. Press **Virtual** on a device's card in the Executors
  tab: the dialog shows the device's USB devices (vendor, product, serial, node;
  **Refresh** re-reads them from the device) to pick from. The Settings tab lists
  every enrolled device's USB hardware, each with a way into that dialog. API:
  `/api/executors/{device}/virtuals` and `/api/executors/{id}/virtual`; audit
  action `executor.virtual`. See `docs/guides/virtual-executors.md`.
- **Executor protocol v14.** Agents report their USB inventory (read from sysfs,
  which the hardened unit leaves visible), whether they can install a packet
  filter, and their engine's OCI runtimes; a start frame can carry a virtual
  executor's firewall and devices, which the device resolves against its live
  hardware at every dispatch — an unplugged device fails the start, naming it.
  A USB device is selected by identity rather than by `/dev/bus/usb` path, which
  changes on every re-enumeration.
- `cloop executor agent install --packet-filter` grants the agent
  `CAP_NET_ADMIN` and netlink so it can install a virtual executor's firewall
  with nft(8); without it such a virtual executor is refused, never started
  unfiltered.
- A denylist for the IP-layer egress filter (`netfilter.Input.DenyCIDRs`),
  compiled ahead of every allow and carried into Kubernetes NetworkPolicies as
  `except` ranges.

### Changed

- **The Event History panel is pushed its rows instead of re-reading them.**
  Every `task_update`, `state_diff`, `task_added`, `task_deleted`,
  `task_mutation` and `run_state` message used to make the dashboard fetch
  `GET /api/event-history` again — every row it held, after a scroll up to
  500 — and each fetch loaded the whole project, every step's output included,
  to return fifty rows: half of all dashboard requests on the hub that runs
  cloop's own project, 244 ms and 155 MB of allocation per request on a journal
  of 50,000 steps. A page is now two index reads (migration 0059 indexes
  `julianday()` of each table's timestamp, so offsets and trimmed fractions
  sort as instants) — about 3 ms at any journal size — paged with `before=`,
  and the rows written since a page arrive as `history_append` messages to the
  project's room, from the watcher that computes its `state_diff`. The panel
  reads only to fill a gap the cursors show: on connect, when the hub's sync
  point is above what it holds, and when a push does not continue from it.
  `offset=` still works; responses no longer carry `total`. A step's output or
  an event's details over 4 KB arrives cut and loads whole when the row is
  opened (`?step=N`, `?event=N`) (Task 20384).
- **Browser telemetry is off by default.** An unset `ui.telemetry.enabled` now
  means off, and the dashboard and the glasses page ask the hub
  (`GET /api/telemetry/config`, `/api/glasses/telemetry/config`) before sending
  anything, so nothing leaves the browser on a hub that collects nothing. A hub
  whose config already says `enabled: true` keeps collecting.
- **The error boundary ships without its comments too.** `errboundary.js`, the
  one first-paint script still served as written, goes through the bundle's
  line-preserving comment stripper: 4.9 KB → 2.6 KB on the wire.
- **`cloop ui --port N` applies its executor policy with its overlay merged.**
  `executors.allow_host_process`, `min_agent_build` and `limits` were applied
  at startup from `config.yaml` alone, before the hub read its overlay. They
  only ever tighten, so the shared file's value always won. An overlay that
  says `allow_host_process: true` now relaxes a shared `config.yaml` that says
  `false`, for that hub alone, as the overlay's per-key merge has always been
  documented to do.

### Fixed

- **Three defects every interactive CLI user met.** (1) Every command whose
  stdout was a terminal asked it for its background colour (OSC 11 and a
  cursor-position request) in bubbletea's package init and waited up to five
  seconds for the reply: under a pty nobody answers — expect, `docker` or
  `kubectl exec -t` from a script, CI with a tty — `cloop status` took 5.05 s
  instead of 0.03 s and its output began with the query. An init that Go runs
  first now gives lipgloss the answer; nothing in cloop reads it, and
  `tests/arch` fails if something starts to. (2) Every project created by
  current cloop printed "warning: .cloop schema is out of date — run 'cloop
  migrate'" on every interactive command, because `cloop migrate` kept a
  version number of its own that the database layer never wrote. It now
  answers from the database's own migrations and warns only for a legacy
  `state.json` project or a database from before them, and `cloop migrate`
  converts and migrates through the database layer instead of its own
  `CREATE TABLE`/`ALTER TABLE` — whose converted databases could not be opened
  at all: the database layer adopted them and then failed at migration 0009
  ("no such table: stuck_tasks"). Such databases are now completed and adopted.
  (3) `cloop config validate --fix` reset every in-progress task to `pending`
  with a bare `UPDATE`, even while a run was executing it. It now leaves the
  plan alone while a run of the project is live — a `cloop run` process in it,
  or a run claimed in the control plane of a hub on this host, judged by the
  rule hub members use — and otherwise recovers the tasks the way the hub
  does: an outcome cloop or the agent had reached (a review gate's rejection,
  a finished agent's `TASK_DONE`) is kept, anything else goes back to
  `pending`, a stale running status is paused, all saved through the database
  layer into the events journal and the audit trail. Every package that opened
  a cloop database with a bare `sql.Open` (taskqueue, globalbudget, taskreplay,
  chaos, the read-only handles of `cloop db backup`/`verify`) now opens it
  under one connection policy: `busy_timeout` on every connection the pool
  opens — taskqueue's `MarkDone` failed instantly with `SQLITE_BUSY` once the
  pool replaced the one connection its pragma had reached — foreign keys,
  `BEGIN IMMEDIATE` for writers, `mode=ro` for readers. A new bare open fails
  `tests/arch`.
- **The Upgrade button no longer moves a device backwards, and "upgrade the
  agent" says how.** The Executors panel's Upgrade button and the fleet
  auto-update policy can only make a device install a published, signed
  release. On a hub running an unreleased build — whose devices speak newer
  protocols than any release — pressing Upgrade prefilled the hub's own
  `dev+g…` version, which no device can download, and `latest` meant v0.0.4,
  which speaks protocol v13: the device's own check could not order its dev
  build against the release, so a v14 device would have installed it and
  dropped a protocol. The hub now resolves `latest` to a tag and refuses, before
  anything is sent, a target that is not a release (400) or whose binaries
  speak an older protocol than the device (409; `force` overrides it), and the
  planner refuses both before it compares versions. The dialog offers the hub's
  own release, or the newest published release that would not lower the
  device's protocol, or — when there is none — only the explanation.
  `cloop executor agent install --upgrade` on a device refuses a staged binary
  speaking an older protocol than the installed one, `--force` to override. And
  every refusal of a device's protocol — revocation, workspace, secret files,
  project state, feature branches, container mode, virtual executors, stored
  firewall rules, attach, remote upgrade — now names the protocol the device
  speaks, the one the hub needs, and the remedy for the hub's build: Upgrade to
  the hub's own release on a hub that is one; on one that is not, build cloop at
  the hub's commit and install it on the device with
  `sudo ./cloop executor agent install --upgrade --insecure-skip-verify`. A
  connected device below the hub's protocol is material version skew whatever
  its build string says. See *Moving a device forward* in
  `docs/architecture/executors.md`.
- **Features run on a remote device against a private repository, come back
  clean, and open their pull request.** Three defects, found on the first live
  run of a feature on a real device (Task 20371), each fixed with a test. A
  feature whose branch rides on a clone of its project's https upstream leased
  the project's GitHub grant as the feature's own path, which no grant names,
  so the dispatch was refused with "no active GitHub grant named … is issued to
  this executor for this project" while the grant was in force. A host-mode
  payload with an environment of its own (any project holding a grant) had its
  checkout as `HOME`, so the harness wrote `.claude.json`, `.claude/` — its
  session transcript among them — and `.config/cloop/` into the repository,
  and a feature's write-back committed them onto the feature's branch; the
  agent now gives such a payload a home of its own beside the tree
  (`.<dir>.home`, mode 0700). And the hub's push of a feature's branch dropped
  its Authorization header, so opening the pull request failed with GitHub's
  403 every time. `scripts/e2e/device-features` drives the whole path through
  the dashboard.
- **Recovery no longer resurrects a task cloop rejected.** A run that died — or
  stopped because its outcome write failed — after the review gate, `--verify`,
  `--script-verify`, abandoned background work or an unanswered clarification
  question had failed a task was recovered from the agent's own `TASK_DONE`, and
  the task's dependents ran on rejected work. The orchestrator now writes each
  decision to `.cloop/artifacts/<id>_verdict.json` before it stores it, and the
  next run's recovery, the hub's dead-run repair and a remote device reading a
  run back all apply that first; the agent's signal is used only when there is
  no decision for the execution. A task whose review had not finished runs
  again rather than counting as done. `cloop compact` and the retention janitor
  remove verdicts nothing will read again.
- **Multi-agent mode obeys the review gate.** `cloop run --multi-agent` built
  options of its own for its architect, coder and reviewer passes, so a gated
  project's sub-agents pushed straight to the remote, unreviewed. Every pass now
  runs as a single agent would — the gate's push hold, the task's directory, the
  project's effort and thinking settings, the background-work notice — and no
  longer stops at a hidden ten-minute limit when no step timeout is set.
- `--script-verify` verified nothing when no step timeout was set, which is the
  default: the script was requested under a deadline that had already passed,
  and the error that followed counted as a pass.
- A project's `capabilities.egress: public` on an executor whose firewall allows
  only a private range handed the project the whole public Internet. It is now
  refused, like the broker-only case: a scope may only remove reach.
- Device passthrough is no longer advertised or attempted under gVisor or Kata.
  Measured on a gVisor host: the node exists in the sandbox and every open of it
  fails with `ENXIO`. The enterprise-hosts guide claimed the combination worked.
- A filtered sandbox resolves through the resolvers its filter opened, named in
  a `resolv.conf` of its own. Dropping private space also drops the engine's
  default resolver — on a cloud VM usually the provider's, in CGNAT space — and
  under gVisor Docker's embedded resolver on `127.0.0.11` is unreachable
  altogether (measured: every lookup `EAI_AGAIN`), so DNS failed inside such a
  sandbox.
- An egress filter is refused under rootless podman, whose networks live in a
  network namespace the host's packet filter cannot see: the ruleset loaded,
  matched nothing, and the sandbox ran unfiltered.
- A task whose harness reported "API Error: Can't reach the API server" was
  recorded as done. An unreachable provider is now an abort
  (`network_unreachable`) that pauses the run and names the cause.
- Revoking a device deletes its virtual executors, each with an audit row.
- The Executors panel's sandbox chip always described a container-mode device's
  network as `none`: the card read a field the API never filled in.
- A run on a hub in strict mode with no isolating executor answered `500` "no
  default executor configured". Strict mode evicts the host driver, which was
  the registry's default, and the empty registry was reported as a broken
  install. It is now the policy refusal: a `409` `host_execution_denied` that
  names the setting and what to configure.

### Security

- **An SSO hub without a role policy says it runs with RBAC off, and one click
  leaves that state.** With `ui.oidc` enabled and neither `role_mappings` nor a
  `default_role` — the upgrade rule, and the shape of a hub configured with
  only `admin_emails` — every identity the issuer authenticates holds every
  permission but executor administration, and quotas never count them. `cloop
  hub doctor` reported that as `rbac.default_role` PASS "deny-by-default", the
  startup banner as `default role "none"`, and Settings → Single sign-on
  pre-selected "none — deny by default", so saving any field of that form wrote
  `default_role: none` and, at the next restart, locked out every identity
  without a mapping. Whether RBAC is in force is now one predicate,
  `authz.Enforced`, that the request gate and every reporter ask, and a
  `tests/arch` gate fails a second copy: the doctor fails `rbac.enforced`
  naming the issuer, `cloop ui` warns on stderr, `/api/me` reports
  `rbac_enforced`, and Settings says *"RBAC is off: everyone who can sign in
  through ‹issuer› has full access"*, shows the default role as saved — unset —
  and offers **Enforce deny-by-default** (`POST /api/config/oidc/enforce`,
  audited as `oidc.rbac.enforced`), which writes `default_role: none` plus an
  admin mapping for the acting admin and keeps every current admin one. A save
  of `ui.oidc` that would switch RBAC on or off is refused with 409
  `rbac_change` unless it carries `confirm_rbac`, which the panel asks for. New
  `ui.oidc.require_rbac: true` (Helm `oidc.requireRBAC`) refuses to start in
  the RBAC-off state. On such a hub audit rows named every actor `local`, and a
  signed-in user outside `admin_emails` could not save the form at all; both are
  fixed. :8888's policy is unchanged (Task 20395).
- **A web page can no longer drive the hub.** No HTTP route checked where a
  state-changing request came from, and every handler decoded its body as JSON
  whatever its `Content-Type` said, so a form with `enctype=text/plain` on any
  page reached any mutating route — on an SSO hub from another port of its host
  or a sibling subdomain (SameSite does not tell origins of one site apart),
  and on a hub without sign-in from anywhere. Now every `POST`/`PUT`/`PATCH`/
  `DELETE` without an `Authorization: Bearer` credential is refused with 403
  `CROSS_ORIGIN` unless the browser's `Sec-Fetch-Site` is `same-origin` or
  `none` — or, from a browser too old to send it, its `Origin` is exactly one of
  the hub's own: the scheme and host it was addressed to, `ui.external_url`,
  the SSO callback's origin, `ui.allowed_origins`. A body must be
  `application/json` (multipart on the three upload routes), else 415
  `UNSUPPORTED_MEDIA_TYPE`, and every handler decodes through one decoder,
  `pkg/jsonbody`, that refuses the rest. The hub sends no CORS header to anyone:
  it used to answer every loopback `Origin`, which let any page on another port
  of localhost read a hub without sign-in. Refusals are counted
  (`cloop_cross_origin_refusals_total`) and audited as `request.origin_refused`.
  A route-table sweep and a Chrome test — a page on another port and another
  site submitting a text/plain form, `no-cors` fetches and a WebSocket — prove it
  (Task 20394).
- **DNS rebinding is refused on a hub without sign-in.** A page on a name the
  attacker controls, re-pointed at 127.0.0.1, was same-origin with a loopback
  hub and could read and drive every API — on a developer's machine, queue a
  task an agent runs with `bypassPermissions`. Such a hub now answers only to
  `localhost`, `*.localhost`, IP addresses, `ui.external_url`'s host, its
  cluster's advertise hosts and the new `ui.allowed_hosts`; any other `Host` is
  421 `MISDIRECTED_REQUEST`, audited as `request.host_refused` (Task 20394).
- **WebSocket origins are matched exactly.** The dashboard socket and the
  executor-agent endpoint admitted every loopback origin and every port of the
  hub's host name; they now require the scheme, host and port of one of the
  hub's own origins (Task 20394). A schemeless `ui.allowed_origins` or
  `ui.allowed_ws_origins` entry means https.
- **`X-Forwarded-*` are believed only from a trusted proxy.** The scheme an
  origin was judged by came from `X-Forwarded-Proto`, believed from any peer
  once `ui.external_url` was https, and the client address the sign-in lockout
  and rate limiter count was the leftmost `X-Forwarded-For` entry — which
  nginx's `$proxy_add_x_forwarded_for` passes through from the client, so
  anyone could reset their lockout per request. The headers are now believed
  from loopback and the new `ui.trusted_proxies` (CIDR list) only, and
  `X-Forwarded-For` is walked from the right; HSTS is still sent whenever
  the public URL (`ui.external_url`, else the SSO callback) is https, and the
  session cookie is `Secure` under
  `cookie_secure: auto` whenever `ui.oidc.redirect_url` is. A proxy on another
  host now needs a `ui.trusted_proxies` entry for `/install.sh` and the
  one-line installer; the Helm chart lists the private pod ranges by default
  (`config.trustedProxies`) and the compose stack its network (Task 20394).
- **`cloop serve` no longer answers every origin with
  `Access-Control-Allow-Origin: *`.** Without a token — its default, on
  loopback — any page on the Internet could read the plan and `POST
  /run/start`. CORS is now granted only to a server with a token, and the same
  origin, media-type and Host rules apply (Task 20394).

- **Executor failover is capped, and a task that takes nodes down is
  quarantined.** A run stranded on an executor that stopped answering was
  re-dispatched to the next healthy one with no ceiling, so a workload that
  takes its node down — a fork bomb, one that exhausts memory, one that panics
  the kernel — went on to take down every enrolled device in turn.
  `executors.failover.max_attempts` (2 by default, `0` for none, at most 10;
  hub-scope, so a per-instance overlay applies) bounds it, decided inside the
  claim that makes a failover exactly-once so that racing supervisors and hub
  members agree. Past the cap the session closes `failover_exhausted`, nothing
  re-dispatches it, and the tasks it was running fail with every lost node and
  when it went unreachable named in the reason — written through the verdict
  sidecar, journalled, and audited as `executor.failover_exhausted`. A task two
  distinct executors went down under is quarantined as a suspected node killer
  (`task.quarantine`), shown in its details and by `cloop executor list
  --inventory` (a new flag), and runs again only after an explicit reset, which
  is audited as `task.quarantine_release`; `--retry-failed` and the
  orchestrator's gate hold it. A failover with nowhere to go now also returns
  the lost node's tasks to pending, as it was always documented to, and a late
  session close no longer overwrites what a failover's claim recorded (Task
  20391).
- **The Projects grid's Run button and a new project's auto-run meet the same
  admission gates as the Overview's Run.** They checked neither the executor's
  access list nor the tenant's daily budget and concurrency quota, so an
  identity left off a restricted executor's access list was refused on the
  Overview and admitted from the project card (Task 20391).
- **The threat model's residual-risk column matches the code again**, and a
  docs gate fails the build when `docs/security/*.md` cites a test that does not
  exist (Task 20391).

- **One credential registry for every scanner; `cloop audit` sees the tokens
  GitHub issues now.** Four places recognise credentials by shape and each kept
  its own list. `cloop audit` matched `ghp_`/`ghs_` followed by 30 letters and
  digits, so it missed `gho_`, `ghu_` and `ghr_` and every installation token
  minted since September 2026 (390 characters, an underscore seven in): it
  reported a clean history over a real leak. Browser telemetry knew only
  `cloop_pat_` and `cloop_glasses_` and stored a GitHub token or an Anthropic
  key in a page's error verbatim; the broker's audit-reason scrubber knew none
  of cloop's prefixes, turned `risk-free` into `ri[redacted]`, and removed only
  the `-----BEGIN` line of a private key; the provider-call audit knew `sk-`
  keys and `Bearer`. All four now use the registry in `pkg/redact` — GitHub
  tokens in both forms for all five prefixes and `github_pat_`, Anthropic,
  OpenAI, AWS, Google and Slack keys, JWTs, PEM private keys, kubeconfig keys
  and tokens, Authorization values, URL passwords, and cloop's own tokens — each
  keeping its own replacement style. `cloop audit` streams the history instead
  of reading it whole and also reports credential shapes in task artifacts
  (*Credentials in task artifacts*); the git-history finding is now named
  *Credentials in git history*. Exact-value redaction of leased material is
  unchanged and still the primary defence. The shapes are listed in
  `docs/reference/credential-patterns.md`.

  An adversarial review before landing (Task 20369) found more, all fixed:
  the first registry rescanned rejected candidates, which made one 2 MiB
  telemetry POST hold a core for hours, and it is linear now; it missed keys
  behind a prefix (`GITHUB_TOKEN=`), escaped JSON, Go headers, `sk-None-` keys,
  URL passwords led by `%`, `$` or `*`, credentials after a percent-encoded
  `=`, and values that run into `[` or hold `!`, `|` or `%2B`; and it matched a
  private-key header with no key, fields across a line break, names in code and
  documentation placeholders. `cloop audit`'s history scan no longer runs
  programs a repository's config names (`gpg.program`, a partial clone's
  `upload-pack`) and now reads replace refs' originals, merges' own changes,
  files marked binary and moved files; its artifact scan reaches
  subdirectories. Broker audit reasons are cut to 8 KiB, and telemetry runs the
  registry before its query-parameter pass.

- **Removing a project closes the dashboards still attached to it.** Live
  streams are filed by project path, so a socket left open on a removed
  project went on receiving whatever was registered at that path next —
  possibly somebody else's project. They are now told the project is gone and
  closed.
- **Hub-scope settings in a per-instance overlay now govern the hub.** `cloop ui
  --port N` merged `.cloop/config.ui-N.yaml` over `config.yaml` for its `ui.*`
  settings, but read every other hub-scope setting from `config.yaml` alone. An
  overlay that set `executors.allow_host_process: false` still let the dashboard
  spawn harnesses on its host. An image allowlist there admitted any image.
  `executors.git_proxy` there started no proxy, so forge credentials went into
  sandboxes as if none were configured. `min_agent_build`, `limits`,
  `auto_install_harness`, the container and Kubernetes drivers, retention,
  backup, dictation and the hub's `github.token` were ignored the same way.
  Every hub-scope read now goes through one overlay-aware accessor, and a source
  gate fails on any new `config.Load` in `pkg/ui` that is not on its
  project-scope allowlist. The configuration reference lists the hub-scope keys.
- **Settings saves no longer leak between dashboards.** On a hub with an
  overlay, saving CI federation or the dictation key rewrote the shared
  `config.yaml`. The overlay hid the change from this hub, and the other
  dashboard reading that file picked it up. Saves now write the overlay when one
  exists (`ui.ci`, `stt.groq_api_key`) and leave `config.yaml` byte for byte as
  it was. Without one, `config.yaml` is rewritten only from itself.
- **`cloop hub doctor --smoke` keeps git tokens out of its sandbox** when any hub
  sharing the directory runs the git proxy, including one enabled only in an
  overlay. A configuration it cannot read counts as enabled. `cloop hub doctor
  --port N` diagnoses the hub on port N with its overlay merged.

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

[0.0.4]: https://github.com/blechschmidt/cloop/releases/tag/v0.0.4
[0.0.3]: https://github.com/blechschmidt/cloop/tree/v0.0.3
[0.0.2]: https://github.com/blechschmidt/cloop/tree/v0.0.2
[0.0.1]: https://github.com/blechschmidt/cloop/releases/tag/v0.0.1
