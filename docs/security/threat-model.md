# Threat model

STRIDE analysis per trust boundary, with what actually mitigates each threat and
an honest account of what does not.

This document is written against the code as it exists, not against an intended
design. Where a mitigation is partial, the "Residual risk" column says so; where
there is none, it says that too. A threat model whose right-hand column is
uniformly "mitigated" is describing a diagram, not a system.

Read [the security model](model.md) first for the boundaries and the
guarantee → test table. The boundary numbering here matches it.

**Assets, in rough order of what an attacker wants:** brokered credentials
(GitHub PATs, kubeconfigs, registry logins), the hub's secret-sealing key,
arbitrary code execution on the hub host, the project state database, the audit
trail's integrity, and the hub's network position (its egress reachability into
private networks).

**Standing assumption:** *the workload is hostile.* It runs code an LLM chose. So
"a task did something malicious" is not a compromise of this model — it is the
scenario the model is designed for. The question is always what the blast radius
is.

---

## ① Browser ↔ hub

| STRIDE | Threat | Mitigation | Residual risk |
| --- | --- | --- | --- |
| **S**poofing | Attacker authenticates as another user | OIDC ID token verified against provider JWKS (RS256/ES256), issuer and audience checked; session cookie is `HttpOnly` so JS cannot read it | Static bearer token is a bearer credential with **admin** rights and no expiry — anyone holding it is admin. Use SSO where you can; treat the token as a root password |
| **S**poofing | Stolen session cookie replayed | `HttpOnly`; `Secure` + `SameSite=Strict` under TLS. A session is a server-side row keyed by the cookie's SHA-256, and it ends at its absolute TTL (`ui.oidc.session_ttl_hours`, 24 h), after `idle_timeout_hours` unused (8 h), when the IdP refuses its refresh token (asked every `refresh_interval_minutes`; needs `CLOOP_SECRET_KEY`), on sign-out, or when revoked — by its user (`POST /api/session/logout-all`), from the Sessions panel (`DELETE /api/sessions/{id}`, `session.admin`), or from a shell (`cloop hub session revoke` with a session id, `--identity` or `--all`; `cloop hub user offboard`) (`TestRevokeThenRequestIsRefused`, `TestIdleTimeoutEndsSession`, `TestRevokedSessionIsRefusedOnNextRequest`) | No device binding: the IP and user agent are recorded, not checked, so a stolen cookie works from anywhere until one of those ends it — and using it keeps the idle clock running, so unnoticed it lasts to the absolute TTL. A revocation is immediate on the hub member that made it and reaches every other member within 30 s (the session cache). It does not close a WebSocket or SSE stream the cookie already opened: streams re-check runtime denies and memberships, not sessions, so contain with `cloop hub role revoke` as well |
| **T**ampering | Request forgery from another origin | `SameSite=Strict` on the session cookie when it is `Secure`, `Lax` when it is not; `wsOriginAllowed` refuses cross-origin WebSocket upgrades (`TestWSOriginAllowed`; the agent endpoint's twin is `TestHubRejectsCrossOriginUpgrade`); the hub never sends `Access-Control-Allow-Credentials`, so a cross-origin request carrying the cookie can only be a simple one, and its answer cannot be read | No HTTP route checks `Origin`; only the two WebSocket upgrades do. `SameSite` is therefore the whole defence against a forged simple request — a form or `text/plain` POST, which handlers decode as JSON whatever its `Content-Type` — and it does not tell origins of the same *site* apart: another port on the hub's host (any local page, on a plaintext loopback hub whose cookie is `Lax`) or a sibling subdomain gets the cookie sent, and `wsOriginAllowed` admits every loopback origin and every port of the hub's hostname. A hub with neither SSO nor a token has no credential to withhold |
| **T**ampering | Clickjacking through the documents the silent renewal frames | Only `/auth/renew` and the OIDC callback are framable, by `frame-ancestors 'self'` and `SAMEORIGIN`; everything else is `'none'`/`DENY`; neither framable document holds a control (`TestOnlyTheRenewalDocumentsAreFramable`) | A script injected *into* the dashboard could frame them — it could also call the API directly, so this widens nothing such a script did not already have |
| **S**poofing | A browser signed into another account at the identity provider renews somebody's session as that account | The renewal's pending login records the session's subject from a cookie-bearing request; an `id_token` for anyone else is applied to nothing and audited as [`session.renewal_mismatch`](../reference/audit-events.md#session) (`TestSilentRenewRefusesADifferentSubject`) | The session's claims stay stale until its user signs in again; a user who really switched accounts sees the sign-in banner |
| **I**nformation disclosure | A page elsewhere reads the renewal's verdict | The verdict is posted to `"/"`, the sending document's own origin, so only a same-origin parent receives it; the dashboard also checks the source frame and origin (`TestRenewDocumentPostsOnlyToItsOwnOrigin`) | — |
| **T**ampering | The public login route used as an open redirector via `return` | `safeReturnPath` keeps only a single-slash path on this origin with no scheme, authority, backslash prefix or control character, and the landing page escapes it for HTML and script (`TestSafeReturnPath`, `TestLoginRefusesAnOffSiteReturn`) | — |
| **D**enial of service | A hub whose cookie the browser refuses bounces a lapsed session between itself and the provider | An automatic sign-in that comes back without a live session is not repeated; the banner explains and leaves the choice to the user (`TestDashboard_UnauthorizedPicksTheRightSignIn`) | — |
| **T**ampering | Downgrade or MITM on the wire | TLS 1.2 minimum, ECDHE+AEAD suites only, server cipher preference; `Strict-Transport-Security: max-age=31536000; includeSubDomains` on every response the hub knows arrived over TLS — its own listener, `X-Forwarded-Proto: https` from a loopback proxy, or from any proxy once `ui.external_url` is https (`TestSecurityHeadersHSTS`, `TestRequestIsTLS`) | No `preload`, so a browser's first plaintext visit is unprotected. Behind a terminator on another host with no https `ui.external_url` the hub sends no HSTS: set `external_url`, or set the header at the proxy. A plaintext deployment never gets it, by design |
| **R**epudiation | User denies making a privileged change | Every privileged allow *and* deny is written to a SHA-256 hash-chained audit trail with actor identity | Chain proves *tampering*, not *deletion of the tail*: truncating the newest rows leaves a shorter valid chain. Export off-box (see the [runbook](../operations/runbook.md#audit-chain-verification)) |
| **I**nformation disclosure | Dashboard leaks another tenant's project | Every route declares a `Scope`; project-scoped routes resolve the project and re-check visibility (`requireVisibleProject`) | Scoping is per-route; a new route that forgets `Scope` is caught by `routeSpec.validate()` only for the *permission*, not for the scope. **Push channels are not routes at all** — see [scope is not permission](#scope-is-not-permission) |
| **I**nformation disclosure | Live harness output crosses a project boundary | Every log chunk is fanned out with `broadcastToProject`; the replay buffer is keyed by resolved `workDir` and reachable only through accessors that take one (`TestLiveLogDoesNotCrossProjectsOverWebSocket`, `TestLiveLogBufferIsUnreachableWithoutAWorkDir`) | Output is redacted of the values a lease delivered, not of a credential the workload obtained another way — that one lands in its *own* project's buffer, where anyone who can see that project can read it ([what is scrubbed where](model.md#what-is-scrubbed-where)) |
| **I**nformation disclosure | Secrets rendered into the UI or an error | Broker never returns plaintext outside a `Material`; error paths and audit rows are redacted, and the broker, the provider-call audit and browser telemetry recognise credentials from one shared registry (`TestBrokeredMaterialIsNeverDisclosed`, `TestBrokerErrorsDoNotEchoCredentials`, `TestEveryScannerCoversEveryCredential`) | Task **output** is redacted of leased values only — a workload that echoes a token it got elsewhere puts it on the dashboard, and `cloop audit` reports its shape afterwards; a credential shape the registry does not know passes every scanner |
| **D**enial of service | Request flood or connection exhaustion | Per-IP token-bucket rate limiting; WebSocket connections bounded per-IP and globally; `/healthz` and `/readyz` bypass auth and rate limiting so probes never lock out an operator; per-tenant quotas (`ui.quotas`: `max_concurrent_tasks` and daily token and cost budgets, bound to identities and groups) admitted check-and-increment under one lock on every path a person starts a run by — `/api/run`, a project card's Run, a new project's auto-run (`TestConcurrentAdmissionNeverOverAdmits`, `TestProjectGridRunTakesAConcurrencySlot`) | Quotas are **unlimited until configured** (`TestQuotaEnforcementIsInertWithoutPolicy`). They count only an identity RBAC resolves — an SSO session on a hub with a role policy, or an API token, charged to its minter; the static token and every caller on a hub whose RBAC is off are never counted. A group binding gives each member that ceiling, not the group one shared pool. The hub's own restarts of a run — resuming one a subscription cap paused, re-dispatching one a lost node stranded — take no slot. Rate limits and connection caps are per hub member, so N members admit N times the per-address rate |
| **E**levation of privilege | Viewer performs an operator action | Deny by default: `oidc.default_role: none`; permission declared per route in `routeTable()`, enforced by `gate()`/`require()`; a route with no permission fails `validate()` at startup | Role comes from an IdP claim — an IdP that lets users self-assign groups hands out cloop roles |
| **E**levation of privilege | A project maintainer mints a stronger role through a [member](model.md#project-members) and acts through them | A grant is capped at the granter's own role on that project — as re-asserted at the provider for `project.share`, not as the session arrived with — and a member above it cannot be changed or removed by them, checked again against the table inside the write; sharing takes `project.share`, held from maintainer up (`TestMembers_ShareOnAHubWhoseDefaultRoleIsNone`, `TestMembers_TheCeilingIsTheRoleTheProviderAssertsNow`, `TestMembers_ARosterChangeIsCheckedAgainstTheTable`) | A maintainer can admit any identity at up to maintainer. Every change is on the trail as [`project.member.grant`](../reference/audit-events.md#projectmember) and its siblings |
| **I**nformation disclosure | A removed member keeps a live stream of the project | Every membership change — through this hub, another hub member (bus), `cloop project members`, or the 5 s re-read — re-checks every open stream and closes the ones that lost the project, after taking them out of its room; a stream between its gate and its room asks again once it has joined (`TestMembers_RevocationClosesALiveSocket`, `TestClusterMembershipChangesReachEveryMember`, `TestMembers_ARevocationBetweenTheGateAndTheRoomStillCloses`) | Up to ~5 s for a change that reaches no bus, e.g. a hand edit of the table |
| **I**nformation disclosure | A member with no role beyond the shared project is listed the hub's other projects | A caller without `project.read` hub-wide is listed only the projects they can read (`narrowToReadable`), and is not sent the projects page's presence list (`TestMembers_AMemberIsNotToldWhoElseIsOnTheProjectsPage`) | — |
| **E**levation of privilege | A roster outlives its project and admits its members to the next project registered at that path | Removing a project from the hub removes its members first — a failure leaves the project in place — and closes every stream attached to it (`TestMembers_RemovingTheProjectRemovesItsRoster`, `TestMembers_RemovingTheProjectClosesItsStreams`) | A membership written by hand for a path the hub does not serve waits there; `cloop project members add` refuses one |
| **E**levation of privilege | Reach code execution on the hub host | Strict mode plus a whole-module call-graph gate (`TestNoHandlerReachesProcessExecution`) | Seven endpoints legitimately touch the host and are *gated*, not removed — the four Claude-login routes, inline replay, task provenance and task reproduce (`TestGatedHandlersRefuseUnderStrictMode`, `TestGatedListsAgree`); two of them, login status and provenance, need only `viewer`. With `allow_host_process: true` — or unset, which reads as true — this row is unmitigated by construction |

---

## ② Hub ↔ remote agent

| STRIDE | Threat | Mitigation | Residual risk |
| --- | --- | --- | --- |
| **S**poofing | Rogue device enrols as an executor | Single-use token, TTL ≤ 24 h (15 min default), checksummed before any DB lookup (HMAC-keyed when `CLOOP_STATE_HMAC_KEY` is set), redeemed via `UPDATE … WHERE redeemed_at = '' AND revoked_at = ''` (`TestEnrollmentTokenIsSingleUse`, `TestEnrollmentTokenSurvivesOnlyOneOfManyConcurrentRedemptions`) | The token is a bearer secret in transit to the device. Deliver it over a channel you trust and keep the TTL short. Without `CLOOP_STATE_HMAC_KEY` the pre-lookup check is an unkeyed checksum: it turns away typos, not forgeries, and the single-use redemption is what holds |
| **S**poofing | Attacker impersonates the **hub** to a device | Agent-side SPKI pinning (`--pin sha256:…`), verified in a `VerifyPeerCertificate` hook (`TestAgentDialUsesPinnedTLSConfig`); `CheckEndpoint` refuses plaintext to non-loopback | `--insecure-transport` disables this. It exists for tunnels that are already protected; anything else is a downgrade. A hub without `ui.tls.cert_file` mints enrollment bundles with no pin, and a device enrolled from one accepts any CA-valid certificate for the hub's hostname |
| **S**poofing | Credential lifted from a hub database dump | Only SHA-256 hashes of the token and credential are stored | A dump of the *device* yields `~/.cloop/agent.json` in plaintext (0600). Device compromise is device compromise |
| **T**ampering | Frames modified or replayed on the wire | TLS provides integrity and ordering; frames are version-bounded and handle-scoped (`TestFrameVersionIsBounded`, `TestHandleScopedFramesRequireAHandle`) | **No application-layer replay protection** — there is no nonce or sequence MAC. Security here rests entirely on TLS |
| **T**ampering | One agent forges status for another's workload | The session binds to one agent identity; handle-scoped frames are checked against it | — |
| **R**epudiation | Device denies running a workload | Each dispatch is recorded in `executor_sessions` with executor id, handle, project path, attempt and the dispatched spec, leased values redacted (`TestDispatchedSpecNeverPersistsLeasedCredentials`), and the tasks the run announced it was working on (`running_tasks`); state changes and failovers are audit rows | Output is attested by the agent itself; a compromised agent can lie about what it ran — including which tasks it announced, which is what a failover charges a lost node to. A session row is best-effort: a dispatch whose row cannot be written runs untracked and is never failed over |
| **I**nformation disclosure | Credentials read off the wire | TLS, with the pin binding *which* TLS peer | Plaintext loopback is permitted by design for local development |
| **D**enial of service | Malicious agent exhausts hub memory | Frame size cap enforced before allocation (`TestOversizedFrameIsRejected`, `TestFrameSizeCapIsSane`); decoders fuzzed for panics (`FuzzFrameDecoding`, `FuzzFrameTruncation`) | An enrolled agent can still hold a connection and heartbeat while doing nothing useful. It can also pin up to 128 MiB (`executor.MaxWriteBackBundleBytes`) of write-back bytes in hub memory per handle the hub tracks for it — running ones and up to 256 retained finished ones — because result chunks are accepted for a finished handle, and again after its bundle was collected. `cordon`/`revoke` are the answer |
| **D**enial of service | Node vanishes mid-task | The supervisor probes about every 30 s (±20 %); a device's probe fails once it has no session or has been silent past the 45 s heartbeat deadline, and three consecutive failures make it `unreachable` — roughly 1½–3 min after it goes silent. Each running session is claimed by rotating its claim token, so it is settled at most once (`TestFailoverRequeuesExactlyOnceUnderConcurrentSupervisors`, `TestFailoverExactlyOnceGuardIsLoadBearing`). The same claim applies `executors.failover.max_attempts` — 2 re-dispatches by default, 10 at most — so racing supervisors and hub members agree (`TestTwoSupervisorsRacingAtTheCap`): past it the session closes `failover_exhausted`, nothing re-dispatches it, and the tasks it was running fail with every lost node and when it went unreachable named in the reason, through the verdict sidecar, journalled and audited as [`executor.failover_exhausted`](../reference/audit-events.md#executor) (`TestFailoverCapStopsANodeKillerAtMaxAttempts`, `TestFailoverExhaustedFailsTheTaskNamingEachNode`). A task two distinct nodes went down under is quarantined as a suspected node killer, audited as [`task.quarantine`](../reference/audit-events.md#task), and runs again only after an explicit reset (`TestRunPM_RetryFailedLeavesASuspectedNodeKillerFailed`, `TestGateTasks_HoldsAQuarantinedTask`). Below the cap a lost node's tasks return to pending with their fail count raised and the recorded spec starts on a replacement; with no candidate they are settled the same way and nothing is started (`TestFailoverRecordsUnplacedSessions`) | Within the cap a node-killing run still takes down `max_attempts` + 1 nodes, and the count starts again with each dispatch a person starts; the quarantine, which persists across dispatches, is what stops the same task doing it again. Which task a node died under comes from the hub's plan for a run on a shared filesystem and, for a run on a device, from the run's own announcements, so a compromised device can pin its loss on another of its project's tasks (a reset releases it); a device whose cloop predates the mark receives it in the seed and ignores it, and with retry-failed on would run the task again. A replacement starts from the stored spec, without the original's leased credentials and project seed. A cordoned or draining node is never failed over. The stranded workload is not stopped: a device that reconnects resumes it beside the replacement |
| **E**levation of privilege | Agent requests credentials beyond its grants | Leases are computed hub-side from grants matching (executor, project); the agent's request cannot widen them | A compromised agent gets everything granted to it — which is the argument for narrow, short-TTL grants |
| **T**ampering | A compromised hub moves devices onto a build of its choosing | The upgrade frame names a version and nothing else; the device resolves it from its own pinned repository and verifies it against the pin for that channel — releases against `release.yml` on a tag, `edge:<commit>` against `edge.yml` on `main`, and only on a device whose operator opted into the edge channel with a drop-in the hub cannot write (`TestAgentRefusesEdgeTargetsWithoutOptIn`, `TestChannelVerificationMatrix`); and never one earlier on `main` than the device's build (next row) | Within those, the hub chooses among the published releases and retained edge builds that are not earlier on `main` than the device's. An edge build is "a commit on `main` that passed CI", not a release — anyone who can push to `main` controls what it contains ([edge channel](../guides/edge-channel.md#limits)) |
| **T**ampering | **Rollback:** a compromised agent or hub has root install an older, genuinely signed build — one from before a fix to the agent or to the root helper itself | Every release and edge build is stamped with its commit's first-parent position on `main` (its sequence), and the installer refuses a staged build whose sequence is lower than the installed binary's, or that carries none when the installed binary does — both read from the binaries' own `version --json`, never from the request or the agent, and from the helper's own identity if the probe of the installed binary fails. Only `--force` on an operator's own `install --upgrade` as root overrides it; the request file's and the frame's `force` cannot, and `--apply-request --force` is refused. The edge manifest names the sequence and commit, and the binary must report both (`TestCheckUpgradeSafetyOrdersBuildsByTheirPlaceOnMain`, `TestApplyUpgradeRequestCannotForceARollback`, `TestUpgradeForceDoesNotRollBackAndAllowRollbackDoes`, `TestInstalledIdentityFallsBackToThisProcess`, `TestApplyUpgradeRequestRefusesAManifestForAnotherBinary`, `TestRequestUpgradeNeverAsksForARollback`) | A device whose installed build carries no sequence — anything from before Task 20380, including every published release so far (v0.0.1, v0.0.4) — is not covered until it is upgraded to a build that carries one (an edge build, or a release tagged after Task 20380); until then a forced frame can move it to any older release. `cloop hub doctor` names such devices under `executors.edge_lag` only if they follow the edge channel. Root on the device can still roll back, by design. The order is `main`'s first-parent history: whoever can rewrite `main` or push a tag can also change what is built, which no ordering protects against |
| **T**ampering | Release assets replaced so an edge device installs another commit's genuine build | The signed manifest names its commit, every archive must hash to what it lists, and the installed binary must report the manifest's version (`TestStageEdgeRefusesAManifestForAnotherCommit`, `TestStageEdgeRefusesASwappedArchive`, `TestExpectVersionBindsTheBinaryToItsSignature`) | Withholding a build is still possible: an attacker who can delete assets makes an upgrade fail, and the dialog then says the build is not published |
| **E**levation of privilege | A workload running as the agent's user uses the remote-upgrade helper to gain root | The helper is root, but what it accepts is what the hub's frame carries — version, force, settle, reason; it takes the channel from systemd's view of the unit, opens the request without following symlinks, bounds it, deletes it first, ignores it when stale and quotes it in its journal only with control characters removed (`TestApplyUpgradeRequestUsesTheDevicesChannel`, `TestUpgradeRequestRoundTrip`, `TestUpgradeRequestCannotForgeJournalLines`) | Such a workload can ask for anything the hub could, and can trigger restarts by filing requests repeatedly; a request for a build earlier on `main` than the installed one — forced or not — is refused (previous row), except on a device whose installed build predates the sequence |

---

## ③ Hub ↔ container runtime

| STRIDE | Threat | Mitigation | Residual risk |
| --- | --- | --- | --- |
| **S**poofing | Something else talks to the runtime socket | None at this boundary — the socket is unauthenticated by design | Socket access is root-equivalent on the host. Restrict it with filesystem permissions; this boundary protects the *host from workloads*, not the socket from callers |
| **T**ampering | Workload writes outside its workspace | `--read-only` rootfs; scratch is a 512 MB `nosuid,nodev` tmpfs; the project directory is the only writable bind cloop makes on its own. `.cloop/sandbox.yaml` mounts only re-expose paths inside it, lease credential directories and a filtered sandbox's `resolv.conf` are read-only, and a host repository enters only through a `local_repo` grant, read-only unless the grant says `writable`; a feature's sandbox gets a staged checkout and an output directory instead of the project directory (`TestContainerArgvNeverBreaksItsOwnSandbox`, `TestSandboxSpecCannotEscapeTheWorkspace`, `TestHostMountReadOnlyGrantCannotBeWritten`, `TestStageSecretFilesWritesThemPrivatelyAndBindsReadOnly`) | The project directory itself is writable by design — that is where work happens — and so is every repository a `writable` `local_repo` grant opened, which is the developer's own checkout (`TestHostMountWritableGrantReachesTheHost`) |
| **T**ampering | Operator config re-opens the sandbox | `ExtraArgs` denylist rejects `--privileged`, `--cap-add`, `--device`, `--security-opt`, `--volume`, `--pid/ipc/uts/cgroupns`, runtime-socket mounts (`TestContainerRejectsSandboxEscapingExtraArgs`); `--device` reaches the argv only from the typed device list a `host_device` grant or a virtual executor fills (`TestDeviceStillBlockedViaExtraArgs`) | A denylist enumerates known-bad flags; a novel runtime flag with the same effect would not be listed |
| **R**epudiation | Which container ran what | Labels carry project and task id; handles map to sessions; `cloop executor reap` finds strays | — |
| **I**nformation disclosure | Secrets visible in the host process table | Forwarded as bare `--env NAME`; the runtime reads the value from its own environment (`TestContainerSecretsNeverEnterArgv`) | Values are still visible in the container's `/proc/1/environ` — to the workload, which already holds them |
| **I**nformation disclosure | Workload reads host filesystem | Mount namespace whose host binds are the project directory, the read-only lease directories and `resolv.conf` the driver stages, and the repositories a `local_repo` grant opened; `.cloop/sandbox.yaml` cannot name a host path | A container escape defeats this. Namespaces are not a VM; set [`executors.container.oci_runtime`](../guides/kata.md) to a Kata runtime for genuinely untrusted code — noting that the project bind mount, and every granted repository, is shared into the guest either way. A `host_device` grant of a partition hands over the filesystem on it |
| **D**enial of service | Workload exhausts host CPU/RAM/PIDs | `--pids-limit` (1024 by default); `--cpus` and `--memory`, with `--memory-swap` pinned to the memory limit so swap cannot be used to exceed it, wherever the executor config, the project's request or an `executors.limits` ceiling sets them (`TestBuildRequest_CeilingBoundsAnOtherwiseUnlimitedContainer`) | CPU and memory are unbounded until one of those sets them. Disk is not capped by this driver — a `resources.disk` request is refused on it — so a workload can fill the project volume |
| **E**levation of privilege | Workload becomes root on the host | Non-root uid derived from the project directory owner (`TestContainerRefusesRootUser`, `TestValidateNonRootUserRejectsRootSpellings`); `--cap-drop=ALL`; `no-new-privileges` blocks setuid escalation | A kernel vulnerability defeats a namespace boundary. A Kata `oci_runtime` moves it to a guest kernel behind a hypervisor; nothing removes it |
| **E**levation of privilege | Workload reaches the host network or another container | `--network=none` by default; host-network spellings rejected (`TestContainerRejectsHostNetworkSpellings`). `executors.container.egress_filter`, a project's `capabilities.egress`, or firewall rules stored for the device or project add one of two mechanisms: `internal: true` puts the sandbox on a network with no route off the host, or a direct-egress filter installs a default-deny nftables ruleset on the sandbox bridge covering **both** the `forward` and `input` hooks, so destinations belonging to the host are filtered too (`TestHostSideFilterCoversHostBoundServices`) | The filter is **off unless configured**: with no `egress_filter`, no stored firewall rules and no `capabilities.egress`, a bridge network still has unrestricted outbound access, and preflight warns rather than refuses (`TestPreflightWarnsAboutUnfilteredEgress`). Bridges and rulesets are keyed by executor *and* confinement — scope, rule fingerprint, egress-proxy port — so sandboxes share one only when confined identically (`TestEgressScopeGetsItsOwnBridgeAndTable`, `TestRulesNamingNeverSharesABridgeBetweenDifferentRules`). A `host_interface` grant hands the sandbox a host NIC that never crosses the filtered bridge; only stored firewall rules refuse that combination (`TestResolveRefusesAHostInterfaceUnderRules`) |
| **E**levation of privilege | Project names a malicious image in `.cloop/sandbox.yaml` | `sandbox.image_policy` — registry/repo allowlist matched on the **parsed** reference, so `evil.example/ghcr.io/x` and `ghcr.io.evil.example/x` are refused; non-ASCII refused as malformed, removing homographs in one rule; optional cosign verification. Denials are audited as [`sandbox.image_denied`](../reference/audit-events.md#sandbox) (`TestProjectSpecCannotEscapeTheImageAllowlist`) | The policy is **off unless configured** — an unconfigured hub allows any image. The shipped Helm chart configures it; a hand-written `config.yaml` must too |
| **E**levation of privilege | Allowed tag repointed between check and pull (TOCTOU) | An accepted tag is resolved to a digest and the digest is what runs; the tag does not survive past the policy check (`TestSandboxImage_PinsTheOverride`, `TestAuthorizePinsAnAcceptedTag`) | An image with no registry digest — built locally, loaded from a tarball — cannot be pinned. It is refused under `require_signature` and warned about otherwise |
| **E**levation of privilege | Signature verification silently skipped | A missing `cosign` binary is a **denial** with an installation diagnostic, never a pass (`TestSignatureRequirementNeverDegradesToASkip`, `TestCosignMissingFailsClosed`) | Verification trusts the cosign binary on the hub's PATH and the keys the operator configured |
| **E**levation of privilege | Unaudited image fetched at task time | `--pull=never` — the image must already be present, so nothing is fetched at task time | Which images are present is the operator's out-of-band `pull`; the policy governs the reference, not who pulled it |

---

## ④ Hub ↔ Kubernetes cluster

| STRIDE | Threat | Mitigation | Residual risk |
| --- | --- | --- | --- |
| **S**poofing | Stolen kubeconfig used elsewhere | Delivered as a lease, held in memory only, released on terminal state; rewritten to contain only allowed contexts and their clusters/users | The credential inside remains a valid cluster credential for its own lifetime — cloop cannot shorten the cluster's token TTL |
| **T**ampering | Workload mutates its own Pod to gain privilege | The chart's Role grants `create/get/list/watch/delete` on Pods, `get` on `pods/log`, `create/patch/delete` on Secrets (the per-run Secrets it writes; `patch` replaces a GitHub App token in a running Pod's lease Secret) and `create/delete/list` on `networkpolicies`; `update`/`patch` on Pods are **denied**, and the Pod rules are asserted in both directions in CI | — for the Pod. CI asserts nothing about the Secret or NetworkPolicy rules, so a `patch` added on `networkpolicies` — the authority to widen a running sandbox's firewall — would not fail it |
| **R**epudiation | Who created this Pod | Pods carry project/task labels; creation flows through the audit trail | Cluster audit logging is the cluster's job |
| **I**nformation disclosure | Env visible to others in the namespace | Documented, not prevented: `Spec.Env` is readable via `get pods` | **Not mitigated by cloop.** Use a dedicated workload namespace with its own RBAC |
| **I**nformation disclosure | Workload reads cluster Secrets | The Role has no read verb on Secrets — `create/patch/delete` only, for the per-run Secrets it writes — and the Pod sets `automountServiceAccountToken: false`, so the workload holds no ServiceAccount credential | A project's own `kubeconfig` grant still reaches its Pod, projected from a per-run Secret — as a session token for the kube guard when it runs, otherwise as the minimised kubeconfig (`TestEverySecretKindOnEveryBackendIsDeliveredOrRefused`). What it can read is that grant's RBAC, not this Role's |
| **D**enial of service | Workload never terminates | `activeDeadlineSeconds` from `executors.kubernetes.active_deadline_seconds`, or the run's own timeout (`TestSpecTimeoutBecomesActiveDeadline`); CPU/memory requests and limits and an `ephemeral-storage` limit as configured, with an `executors.limits` ceiling filling any limit left unset; `max_concurrent` caps the executor's Pods. The Helm chart sets 7200 s, 250m/2 CPU, 512Mi/4Gi memory and 8Gi | Outside the chart nothing is set by default: `active_deadline_seconds: 0` is unbounded (`TestBuildPod_ZeroDeadlineIsOmitted`), and a Pod with no configured limits is bounded only by the namespace's `LimitRange`. A tight scheduling loop can still exhaust namespace quota; set a `ResourceQuota` |
| **E**levation of privilege | Workload escapes the Pod | `runAsNonRoot`, read-only rootfs, all capabilities dropped, `seccompProfile: RuntimeDefault`; `executors.kubernetes.runtime_class` puts every Pod on a [Kata node pool](../guides/kata.md#kubernetes) when the cluster has one | Standard container isolation caveats apply to the default runtime. cloop names a RuntimeClass; whether that class is really Kata, and whether the node enforces it, is the cluster's to answer |
| **E**levation of privilege | Project names a malicious image, or a tag a node resolves later | The same `sandbox.image_policy` governs the Pod builder, and the digest is what lands in the container spec (`TestPinnedDigestLandsInTheContainerSpec`, `TestPolicyReachesTheExecutorThatRunsTheImage`) | The control plane cannot read a cluster's image store, so a tag **cannot** be pinned here — only required to arrive pinned. Without `require_digest: true` a kubelet resolves the tag whenever it schedules, and the artifact that runs is not the one anything evaluated. The chart sets it |
| **E**levation of privilege | Workload reaches other cluster services | With `executors.kubernetes.egress_filter` enabled, a `NetworkPolicy` per Pod selecting that Pod alone by its handle-id label, compiled from the same policy the container driver's ruleset is (`TestBothBackendsRefuseTheSameDestinations`); `policyTypes` names `Ingress` with no ingress rules, so inbound is denied too | `egress_filter` is off by default, so an unconfigured hub is unchanged: the Pod joins the cluster network and the cluster owns the restriction. A `NetworkPolicy` is inert unless the CNI implements one — flannel does not, and the API server stores the object regardless. A project's `capabilities.egress` and stored firewall rules are refused unless enforcement is proven by `cloop hub doctor --probe-network-policy` (a verdict lasts 30 days) or asserted with `network_policy_enforced: true` (`TestCapabilities_EgressScopeFollowsEnforcement`, `TestRulesNeedAClusterThatEnforcesNetworkPolicy`). The executor's own `egress_filter` is installed either way, and the `egress-enforcement` preflight finding is OK only on a proof or an assertion, a fail on a refuting probe, and a warning otherwise (`TestPreflight_EnforcementFindingTracksTheEvidence`) |

---

## Cross-cutting: the sandbox's network position

The hub's reachability into private networks is on the asset list at the top of
this document, and until recently the only thing guarding it was an HTTP proxy.
That was honest but narrow: `pkg/egressbroker` checks hosts, ports, methods,
quotas and the SSRF block set beautifully, and it only ever sees traffic a
workload chose to send it. **A harness that opened a raw socket, ran
`curl --noproxy '*'`, resolved over DoH or spoke anything that was not HTTP
walked past every one of those checks** — not around them, past them; the
allowlist was never consulted. Both drivers said as much in their own comments
(*"it does not filter egress"*), and both left the sandbox with unrestricted
outbound access the moment an operator turned the network on. Given the
standing assumption above — the workload is an LLM running attacker-influenced
code out of a git repository — this was the widest gap in the model.

What binds it now is a filter at the IP layer, compiled from the same
authorisation by `pkg/netfilter` and enforced by the kernel or the CNI rather
than by the workload's cooperation. What it cannot do is enforce a *hostname*
allowlist, and that limit is structural.

| STRIDE | Threat | Mitigation | Residual risk |
| --- | --- | --- | --- |
| **I**nformation disclosure / **E**levation of privilege | A compromised harness exfiltrates data or moves laterally, ignoring `$HTTP_PROXY` | An IP-layer filter compiled by `pkg/netfilter` from the same authorisation the proxy enforces, installed as nftables on the sandbox bridge or as a per-Pod `NetworkPolicy`. Default deny, no configurable default verdict, `ProtoAny` on every drop so ICMP and SCTP are covered, silent drops so a probe learns nothing (`TestNoCompiledPolicyReachesBlockedSpaceByAccident`) | It binds *addresses*. A host allowlist becomes "every public address on these ports" — see the row below. And it is **off unless configured** |
| **E**levation of privilege | A host allowlist is relied on for a workload that dials directly | The widening is opt-in (`allow_public_internet`), never inferred from the presence of host patterns, and every rendering of the policy carries a warning naming the patterns and what they became — an nft comment, a `NetworkPolicy` annotation, an `egress-scope` preflight finding | **Unfixable at layer 3.** `*.github.com` is a name and a packet carries an address. The narrow configuration is `internal` mode: no route off the host, and the hub's egress proxy, answering at the bridge's gateway, enforces the host allowlist. The gateway is the hub's host, though, and `internal` alone installs no ruleset, so anything else listening there or on every interface — the dashboard's port, by default — is reachable too; bind those narrowly, or add direct rules, whose ruleset filters host-bound destinations on its `input` chain |
| **E**levation of privilege | A sandbox reaches the cloud metadata service | `169.254.169.254/32` is dropped by prefix in both the proxy's block set and the compiled filter, ahead of the link-local drop that contains it so the *reason* reaching the audit trail is the specific one. At the proxy only a CIDR that names the address exactly waives it — a grant whose `--cidrs` merely contains it is refused (`TestWideCIDRsCannotBypassTheBlockSet`, `TestMetadataStaysBlockedUnderAnAcceptedGrant`) | A grant of `169.254.169.254/32` is a real hole by intent, and is meant to be a sentence somebody wrote. The filter's own allow lists — `egress_filter.allow_cidrs` and the dashboard's device and project firewalls — refuse only a `/0`: a containing prefix such as `169.254.0.0/16` written there compiles ahead of the metadata drop and opens it on its ports |
| **S**poofing | A blocked address written in a form the filter does not recognise | Both layers see through the v4-in-v6 spellings; the filter drops the NAT64, 6to4, IPv4-translatable and IPv4-compatible prefixes wholesale because a packet filter cannot unwrap an embedded address (`TestFilterAgreesWithBrokerOnNamedAddresses`, `TestFilterAgreesWithBrokerOnASweep`) | The wholesale drop is stricter than the proxy: `64:ff9b::8.8.8.8` is a public address the proxy allows and the filter refuses |
| **T**ampering | Operator input injects a rule into the host's firewall | Table, chain and interface names are validated against a grammar narrower than nft's; rule comments — built partly from operator-supplied CIDRs — have every character that could end the string or the line replaced, and are truncated on a rune boundary (`TestCommentInjectionCannotEscapeTheString`, `TestRenderNftablesRefusesUnsafeNames`) | The ruleset is applied by shelling out to `nft(8)`, so it inherits whatever that binary is on the `PATH` of the process applying it — the hub's, or a device agent's, which hands that one child `CAP_NET_ADMIN`. The driver looks the binary up again for every sandbox network it provisions or tears down |
| **D**enial of service | The filter fails to install and the sandbox starts anyway | A failed install fails the `Start`. Producing a working sandbox with none of the requested filtering, silently, is the one outcome worse than refusing to run | An `nft` that is missing, or a control plane without `CAP_NET_ADMIN`, therefore stops `filtered` sandboxes from starting at all. Preflight reports it as `fail` with the two fixes (install nftables and grant the capability, or switch to `internal` mode, which needs neither) |
| **E**levation of privilege | The workload starts before its filter does | The ruleset attaches to the *bridge*, from the host side, and the bridge exists from the moment the runtime creates the network — strictly before any container can join it. The alternative (start it, find its PID, `nsenter`) has a window and is not what the driver does | Applies to the container driver. In Kubernetes the `NetworkPolicy` is created alongside the Pod and the CNI programs it on its own schedule |

---

## Scope is not permission

The row above says a new route that forgets `Scope` is caught only for its
permission. A cross-tenant log leak in the WebSocket hub showed that the gap is
wider than "routes": **the push channels are not routes**, so no amount of
route-table validation reaches them.

The two controls answer different questions, and passing one says nothing about
the other:

| | Question | Enforced by | Failure looks like |
| --- | --- | --- | --- |
| **Permission** | *May this actor read this kind of thing?* | `Perm` on the route, `gate()` / `require()` | 403 for someone who should have been allowed, or a viewer performing an operator action |
| **Scope** | *Whose data is this, and is this actor one of them?* | `Scope` on the route, `resolveWorkDir` + `requireVisibleProject`, and on push channels `broadcastToProject` | A correctly-authenticated, correctly-authorised operator is shown **another tenant's** data |

A scope failure is the more dangerous of the two because everything about it
looks healthy. The recipient is signed in. Their role permits reading live
output. The audit trail records no denial, because nothing was denied. Only the
*subject* of the data is wrong — and the disclosed party performed no action
and sees no trace.

The concrete bug (Task 20189): `broadcastLog` wrote each chunk of live harness
output to every SSE client and then iterated **all** of `s.hubClients`, which is
`map[workDir]map[*hubClient]struct{}` — a per-project room map, walked as if it
were one flat set. The correct primitive, `broadcastToProject`, already existed
and was already used correctly one function away by `broadcastStateDiff`. Under
it sat a deeper problem: the replay buffer was a single global `[]string` on
`Server`, so the three replay sites (WebSocket connect, SSE connect,
`GET /api/livelog`) *could not* have been correct — `handleLiveLog` even
resolved a `workDir` and then used it only for a liveness probe. There was one
buffer, so there was nothing to be right about.

Three things this generalises to:

1. **Scope is a property of the data, not of the request.** The route table
   checks the request. A broadcast has no request — by the time a chunk is
   fanned out, the identity that caused it is gone and the identities receiving
   it were established on other connections entirely. Anything that fans out
   has to carry its subject with it.
2. **Prefer making the mistake unsayable to auditing for it.** The fix was not
   a `workDir` check bolted onto each read site; it was deleting the global
   buffer. Live output now lives in a map reachable only through accessors that
   take a `workDir` first, so a handler that has not resolved a project cannot
   name a room, and `TestLiveLogBufferIsUnreachableWithoutAWorkDir` fails the
   build if a future edit reintroduces either the direct map access or an
   unkeyed field on `Server`.
3. **"Global" is a legitimate scope — state it, don't default into it.** Three
   other unscoped `s.hubClients` walks were audited in the same pass and left
   alone: `broadcastAuditAppend`, `broadcastExecutorUpdate`,
   `broadcastSecretsUpdate`. The audit trail, the executor fleet and the secret
   inventory are hub-wide resources; there is no owning project to key them on.
   Their reach *is* wider than the permission to read the underlying rows,
   which is exactly why each envelope carries only an event verb and an opaque
   id, and clients re-read the RBAC-gated endpoint for anything more. That
   trade is now written at each call site so the next reader can tell a
   deliberate global from an overlooked one.

### The same class on the subscription path (Task 20197)

Task 20189 made every *broadcast* carry its subject. What it did not reach is
how a stream acquires a subject in the first place, and two of those were
wrong:

- **The connect burst read the wrong project.** `handleEvents` resolved the
  stream's project into `c.workDir`, then built its opening state frame from
  `s.WorkDir`. Every SSE client's first frame was the primary project's full
  task list regardless of the `?project_idx` it asked for — deterministic, not
  a race, on any network where a proxy blocks WebSocket upgrades. The live-log
  replay eight lines below it is the site Task 20189 fixed; the snapshot above
  it was missed.
- **An index-less stream defaulted into a project.** `resolveWorkDir` falls
  back to `s.WorkDir` when no `?project_idx` is given, which is right for a
  request and wrong for a subscription. The dashboard's projects landing page
  holds a stream while no project is selected, so it was subscribed to the
  primary project and primed with its state, live log and run flag — a project
  the viewer may hold no claim to. Those frames were then still arriving when
  the user clicked into a different project, and the client rendered them,
  which is the user-visible bug this task was filed for: *another project's
  tasks on the tasks page.*

Both are point 3 restated from the other side. "No project selected" is a
legitimate scope; defaulting it into "the primary project" is the same
overlooked-global mistake, and it is now stated instead: the client sends
`?scope=global`, the server puts that stream in a room no `broadcastToProject`
call can name, and it is primed with nothing.

The client half is worth recording separately, because it is the part a
server-side rule cannot enforce. A frame carries no project id — the identity
lives in the subscription — so a frame is only interpretable together with the
stream that delivered it. `close()` on a WebSocket starts a handshake and
returns; frames already in flight still arrive. The receiver therefore has to
freeze the scope at the moment it opens the stream and check it on delivery,
which is what `_scopeAccepts` in `04-realtime.js` does. The guard it replaced
asked `selectedProjectIdx === null` — *is a project selected*, not *is this
frame for the project that is selected*.

This bug class had been re-fixed seven times (Tasks 150, 152, 163, 168, 8000,
20013, 20018), each time behind a test that greps the front end as text.
Ordering is not a property text can express, so the regression test runs the
real bundle in node against a DOM shim and delivers the frames in the order
that corrupts the view (`pkg/ui/scoping_test.go`,
`pkg/ui/testdata/scoping_scenarios.js`). Five of its seven scenarios fail
against the parent commit.

---

## Vulnerabilities found while building this

Recorded because a threat model that lists only theoretical threats is less
useful than one that lists the threats that were actually present. All are
fixed and all have a regression test.

**A workload that took its node down was carried to every node in turn.**
Executor failover moved a session stranded on an unreachable node to the next
healthy one with `Attempt + 1` and no ceiling, and returned its tasks to pending
for the replacement to pick up. A fork bomb, a workload that exhausts memory, or
one that panics the kernel therefore took down the next node, and the next,
until every enrolled device had gone down once — and a person pressing Run
afterwards started the cycle again on the same task. The table above said so
in its own residual-risk column. Fixed in Task 20391 by `executors.failover.max_attempts`,
decided inside the claim's one conditional `UPDATE` so that supervisors and hub
members racing for a session cannot disagree about it, and by quarantining a
task two distinct nodes went down under until an explicit reset
(`TestFailoverCapStopsANodeKillerAtMaxAttempts`, `TestTwoSupervisorsRacingAtTheCap`,
`TestRunPM_RetryFailedLeavesASuspectedNodeKillerFailed`). Building it found a
second, quieter defect: the session watcher's close overwrote whatever state a
failover's claim had recorded once the dead node's stream finally ended, so a
claimed session read as `failed` and its chain disappeared from the record
(`TestCloseLeavesAClaimedSessionAlone`).

**The Projects grid's Run button skipped the executor access list and the
quotas.** `POST /api/run` admits a run through the executor's audience, the
daily budget and a concurrency slot. `POST /api/projects/{idx}/run` — the Run
button on a project card — and a new project's `autoRun` started the same run on
the same executor and checked none of them, so an identity an administrator had
left off a restricted executor's access list was refused on the Overview and
admitted one click away, and a tenant at its concurrency cap could start one
more run there every time. Found re-verifying this document's residual-risk
column in Task 20391, which also gave both paths the same gates
(`TestProjectGridRunHonoursTheExecutorAudience`,
`TestProjectGridRunTakesAConcurrencySlot`,
`TestNewProjectAutorunHonoursTheExecutorAudience`).

**The downgrade guard could not order two builds of `main`, so root would roll a
device back on request.** Since the edge channel (Task 20376) a device follows
the hub's own build: its unprivileged agent files `upgrade-request.json`, and
the root helper installs whatever `edge:<commit>` it names once cosign has
verified it against `edge.yml` on `main`. Every retained edge build passes that
— up to thirty of them — and the guard meant to stop a device moving backwards
compared versions, which for two `dev+g<sha>` builds are "not comparable", so
only the protocol was checked. A compromised agent process, or a compromised hub,
could therefore have root install any older signed build at the same protocol,
including one from before a fix to the helper itself; the request's `force` flag
waved through even a protocol downgrade, so an old release was reachable too. The
signed manifest's `built_at` could not order them either: it is when a build ran,
and a re-run of an old commit is "newer". Fixed in Task 20380 by stamping every
build with its commit's first-parent position on `main` — build scripts, signed
manifest (schema 2) and `cloop version --json` — and refusing in the installer a
staged build earlier than the installed one, read from the binaries themselves,
overridable only by a local root `--force` and never by the request or the hub
(`TestApplyUpgradeRequestCannotForceARollback`,
`TestCheckUpgradeSafetyOrdersBuildsByTheirPlaceOnMain`). The schema-1 manifest
is still published beside schema 2: the code already on devices reads nothing
else, and dropping it would have stranded every one of them off the channel
(`TestTheSchema1ManifestIsWhatAnOlderReaderAccepts`).

**`--cidrs 0.0.0.0/0` waived the entire SSRF block set.** An explicit CIDR is
what waives the block set — that is the design, and it is why there is no
blanket `allow_private` flag and why reaching the metadata service is meant to
be a sentence an operator writes out as `169.254.169.254/32`. A `/0` was that
blanket flag spelled differently: one grant flag turned off cloud metadata,
loopback, and the operator's entire internal network at once. So was any prefix
merely *containing* `169.254.169.254` without naming it — `169.254.0.0/16`
reaches the credentials of the host the hub runs on, which on a cloud instance
is the whole account. Fixed in `egressbroker.validateAllowPrefix`, at grant
time where the operator sees the message, with `pkg/netfilter` refusing the same
shapes so the two layers cannot disagree about it
(`TestWideCIDRsCannotBypassTheBlockSet`,
`TestGrantsThatWouldRemoveTheBlockSetAreRefused`).

**The host-side ruleset filtered the Internet and left the host open.** The
first version had a `forward` chain and nothing else. But the routing decision
picks the hook: destinations the host forwards on reach the `forward` hook,
while destinations that belong to the host itself — the bridge gateway, any
address bound on any of its interfaces — reach the `input` hook instead. So a
sandbox under a policy that dropped `172.16.0.0/12` could still open a
connection to a service on the host's own `172.x` bridge address, which is
precisely the lateral movement the block set exists to refuse. Found by testing
against a real container, not by reading the rules. Fixed by rendering both
hooks with the same rules, since which hook a destination takes is a fact about
the host's routing table and not a security boundary
(`TestHostSideFilterCoversHostBoundServices`, `TestBridgeFormFiltersBothHooks`).

**Project creation was unconfined, which made project deletion an arbitrary
delete.** `POST /api/projects/new` ran `filepath.Abs` + `os.MkdirAll` on the
caller's string with no confinement at all, so a relative `dir` resolved
against the *hub process's* cwd and escaped through `../../../..`, while an
absolute one simply landed wherever it pointed. On its own that is a
directory-creation nuisance. The chain is what matters: the created path is
registered, and `DELETE /api/projects/{idx}?delete_root=true` then
`os.RemoveAll`s it behind a guard that rejected only `""`, relative paths,
`/` and `$HOME` — `/etc`, `/usr`, `/var` and `/home` all passed as "safe".
Because `MkdirAll` returns nil for a directory that already exists, two
`project.write` calls were an arbitrary-directory-deletion primitive. Fixed by
giving creation and deletion one shared predicate, `isSafeProjectRoot`, which
now also refuses system subtrees and bare top-level directories while leaving
`/var/lib/cloop/projects/…` — where the packaged image puts state — working
(`TestIsSafeProjectRootRejectsSystemPaths`,
`TestProjectCreateRejectsSystemDirectories`).

**A 60-byte read request returned a 109 MB response.** `/api/analytics`
validated that `?from=`/`?to=` *parsed* as dates but never how far apart they
were, and `time.Parse` accepts years 0000–9999. The handler builds one label
per day in the window and sizes a `float64` slice per provider from it, so
`?from=0001-01-01&to=9999-12-31` drove a ~3.65M-iteration loop; measured on an
empty project it returned 109,562,327 bytes in ~2s. The route carries `read`,
the lowest permission on the hub, and the per-IP limiter defaults to 20 rps, so
a viewer — or anyone at all on a hub with auth misconfigured — could OOM the
daemon with a handful of concurrent GETs. Fixed by clamping the window to
`maxAnalyticsWindowDays` and normalising an inverted range, which also keeps
every dataset the same width as the label axis
(`TestAnalyticsBoundsTheDateWindow`, `TestAnalyticsAcceptsOrdinaryWindows`).

**Mutating verbs were served by read-only routes.** Ten routes are registered
without a method prefix, so `http.ServeMux` hands them every verb, and none of
the handlers checked `r.Method`: `DELETE /api/state` returned 200 and the full
state, `DELETE /api/projects` returned 200 and a 37 KB project listing. No data
was destroyed — the handlers only read — but a mutating verb was being
authorized by the `read` permission, and a client that dropped the index from
the real `DELETE /api/projects/{idx}` got a cheerful 200 from a listing instead
of an error. Fixed in `gate()` rather than per-handler, expressed as "a
mutating verb is never authorized by a read permission" so it also holds for
routes added later, and placed ahead of the `authzActiveFor` short-circuit so
it applies in single-tenant deployments too
(`TestReadOnlyRoutesRejectMutatingMethods`).

**Live harness output was broadcast to every project's dashboard.** One
project's raw stdout — file paths, source excerpts, anything the workload
echoed — reached every open dashboard on the hub, including projects belonging
to other identities, and was replayed from a single global buffer to any client
that connected afterwards. See [scope is not permission](#scope-is-not-permission)
for the anatomy; fixed by routing every chunk through `broadcastToProject` and
partitioning the buffer by resolved `workDir`.

**The Groq API key was passed on the argv.** `/api/voice` appended a
caller-supplied `--groq-api-key` to the subprocess argv, where
`/proc/<pid>/cmdline` exposes it to every local user for the lifetime of the
child — the same exposure `install_script.go` already refuses for enrolment
tokens. Fixed by passing it in the environment, which `cloop listen` already
reads as `GROQ_API_KEY`; the plumbing appends to the inherited environment
rather than replacing it, since `applyLease` reads a nil `Spec.Env` as
"inherit `os.Environ()`" — on the host driver. On an isolating executor it no
longer inherits anything; see the next entry.

**The hub's master sealing key was forwarded into every sandbox that held a
grant (Task 20234).** `applyLease` seeded `Spec.Env` from `os.Environ()`
whenever the caller left it nil, which every dispatch from `handleRun` does.
Every name in `Spec.Env` is then forwarded into the workload — the container
driver emits a bare `--env NAME` per entry — so the hub's entire process
environment crossed the isolation boundary into a container running
model-authored code. On a hosted deployment started from `.cloop/hub.env` that
environment contains `CLOOP_SECRET_KEY`, the master key that unseals *every*
credential in the broker, and `CLOOP_UI_TOKEN`, which bypasses RBAC and sees
every project on the hub. A sandbox leased one repository-scoped token was
handed the keys to the store that token came from, which inverts the entire
point of [scoped grants](#cross-cutting-the-secret-and-egress-brokers).

It applied only to a project that *held* a grant, because `applyLease` returns
early on an empty lease — so it was live on exactly the enterprise path and
absent from the one a developer tries first. It was invisible to every existing
test: the container suite asserts credentials never reach the *argv*, which was
true, and nothing asserted what reached the environment.

Fixed by making the inheritance conditional on `executor.IsolatesFromHost`: a
host-executed harness still inherits, because it is a process on this machine
that would have had that environment anyway and needs `PATH` and `HOME`; an
isolated workload gets exactly the leased material layered on its image's own
environment, and anything else it needs is a grant. The same fix removed a
second symptom — the host's `PATH` was replacing the image's inside the
sandbox, so a `sh` that existed at `/bin/sh` could not be found.

Found by building the end-to-end circuit in `tests/flagship`, which is the
first test to run a real task through an isolating executor rather than against
a fake. Guarded by `TestIsolatedExecutorDoesNotInheritTheHubEnvironment`,
`TestHostExecutorStillInheritsTheEnvironment` and
`TestUndeclaredIsolationIsTreatedAsHostExposure`, and end to end by the
flagship circuit, which has the sandbox report whether it can see either
variable and fails if it can.

---

## Cross-cutting: the secret and egress brokers

| STRIDE | Threat | Mitigation | Residual risk |
| --- | --- | --- | --- |
| **S**poofing | Executor claims another's identity to collect its grants | Subject matching is exact — canonicalised project paths (`/srv/app-staging` does not match `project:/srv/app`), exact executor ids, all-keys label selectors | Label selectors are only as trustworthy as the labels, which are operator-assigned at enrolment |
| **T**ampering | Holder widens a delivered credential | Enforced *by construction* for `kubeconfig` (contexts, and the clusters and users they name), `registry` and `env`: the payload is rewritten before delivery and a narrower payload cannot be widened. A `github_app` grant delivers an installation token GitHub mints for the grant's repositories and permissions only, so GitHub refuses the rest, REST calls included (`TestLeaseMintsScopedInstallationToken`). With `executors.git_proxy` on neither GitHub kind enters the sandbox (`TestGuardedPATNeverReachesTheSandbox`); with `executors.kube_guard` on, neither does the cluster credential | Both monitors are **off by default**. Without the git proxy, `github_pat` is enforced *at use* by a git credential helper — it binds `git`, not a direct REST call. Without the kube guard a kubeconfig grant's `--namespaces` and `--verbs` are recorded but not enforced: the pinned namespace is only `kubectl`'s default. `egress_proxy` enforcement lives in the executor's network policy |
| **E**levation of privilege | Sandbox holds a forge credential and pushes somewhere it was not scoped to | Without the proxy: the workspace PAT is leased for one `git fetch` — and, under `executors.write_back: push` (off by default), held in the device agent's memory for the run's write-back push — and the write-back branch rule (`cloop/`) is checked in `pkg/executor` and re-checked by `pkg/writeback`. With [`executors.git_proxy`](../git-interception-proxy.md) enabled the PAT never enters the sandbox — it gets a session token for a proxy the hub runs, which evaluates the branch allowlist against the push's own ref-update list, refuses all-or-nothing, and audits the attempt as [`gitproxy.push_denied`](../reference/audit-events.md#gitproxy) (`pkg/gitproxy: TestPushToProtectedBranchIsRefused`) | **Off by default**: an un-configured hub delivers the PAT into the sandbox, where the branch rule is a convention the workload can ignore — and a push that ignores it is first noticed as a force-push notification on the forge. Even enabled, the proxy decides *where* a push may go, not what is in it; fast-forward enforcement and branch protection stay the forge's job. A *workspace* session — cloop's own fetch and write-back push — lives for `session_minutes` (60 by default, 720 at most) from dispatch rather than for the run, so anything that lifts it out of the sandbox can use it until then, unless its lease is revoked in the Secrets panel. A session a GitHub *lease* mints for the workload's own git ends with that lease — when the run ends, when the lease is revoked, or when it lapses after a grant revocation — or at `session_minutes`, whichever is first |
| **R**epudiation | Who granted this access | Every grant, revoke and lease decision is audited with actor, subject, constraints and reason (`TestSecretBrokerDecisionsNeverCarryMaterial`) | — |
| **I**nformation disclosure | Material lands on disk or in logs | Sealed at rest (AES-256-GCM); materialised into a 0700 tmpfs dir (`/dev/shm` where available); zeroed and removed on exit; never in `Error()` strings or audit rows | Where `/dev/shm` is unavailable the fallback is `os.TempDir()` — on the hub, in a container's staging directory and on a device — which may be disk-backed, hence the explicit zeroing. On Kubernetes the files sit in a per-run `cloop-lease-*` Secret and leased environment values in the Pod spec, both in the cluster's datastore for the run and readable by whoever may read them in that namespace, and are deleted, not zeroed |
| **D**enial of service | Revocation does not take effect | A lease's deadline is at most 15 min out; while its run lives a keepalive extends it in place, re-checking every grant it carries, so a revoked or expired grant refuses the extension and the lease lapses on its current deadline (`TestExtendRefusesARevokedGrant`, `TestLeaseKeepaliveStopsOnARevokedGrant`). Revoking the *lease* (Secrets panel, `POST /api/leases/{id}/revoke`) scrubs every holder at once; egress revocation tears down **live sessions** at once on the hub member holding them, within a minute elsewhere | Revoking a *grant* reaches material already delivered only when its lease lapses — up to 15 minutes — and the janitor then takes back only what the hub and remote agents hold: a device's lease files (an unreachable device's on reconnect), a host-process workload's lease directory, the lease's git-proxy and kube-guard sessions and App tokens. A hub-local container's staged files and a Pod's lease Secret stay until the workload exits, and an environment variable stays in any running process. To cut access instantly, revoke the lease with `action: kill` |
| **E**levation of privilege | SSRF into the hub's private network | Loopback, RFC1918 and link-local are blocked unless explicitly listed in `--cidrs`; cloud metadata (`169.254.169.254`) requires a CIDR that names it exactly; a `/0`, and any prefix containing the metadata address without naming it, are refused at grant time (`TestWideCIDRsCannotBypassTheBlockSet`) | Granting a private CIDR is a real hole by intent — grant the narrowest prefix and port |
| **E**levation of privilege | DNS rebinding between check and dial | Resolve-once pinning: the name is resolved once, every resolved address is policy-checked, and the dial goes to the checked literal | — |
| **E**levation of privilege | Exfiltration through an allowed host | Per-session byte quotas (`--max-up`, `--max-down`), enforced mid-stream | CONNECT tunnels are opaque — cloop holds no key for the origin, so it sees bytes, not content. `--methods` gates plain HTTP only |

## Cross-cutting: hub members

Several `cloop ui` processes may serve one control plane as a
[hub cluster](../architecture/hub-cluster.md), forwarding to each other the
requests only one of them can answer. The members trust each other exactly as
much as a single hub trusts itself — they share its database — so what needs a
boundary is the channel between them, which a client can also reach.

| STRIDE | Threat | Mitigation | Residual risk |
| --- | --- | --- | --- |
| **S**poofing | A client poses as a member to skip the per-address rate limit, claim another address in the audit trail, or reach `/api/internal/cluster/*` | Every forwarded request carries an HMAC over the sender, the recipient, a timestamp, a nonce, the method, the URI and the original client's address, keyed by a secret kept in the control-plane database; a request whose claim fails verification is refused with `403`, never served as an ordinary one (`TestForgedAndReplayedPeerClaimsAreRefused`, `TestClusterRefusesForgedPeerClaims`) | Anyone who can read `state.db` holds the key — and could already rewrite every table the hub trusts |
| **S**poofing | A captured forwarded request is replayed | The nonce is single-use at its recipient within the two-minute skew window, and the signature names the recipient, so the capture is refused everywhere else (`TestAPeerRequestIsGoodOnlyAtItsRecipient`) | — |
| **E**levation of privilege | Forwarding launders a request past authorization | The owner re-authenticates the forwarded caller from its own cookie or token and applies the route's permission as if reached directly; a member vouches only for the client's address | — |
| **I**nformation disclosure | Forwarded requests carry session cookies and tokens across the network | Members advertise `https://` URLs where others can observe the traffic, and verify peers against the system roots, their own certificate and `ui.cluster.peer_ca_file` | The default is plain HTTP on loopback, and the Helm chart's is plain HTTP between Pods — safe only because every member is on one node, which a cluster requires anyway |
| **T**ampering | Two members act on one run, or one agent | Runs, agents and in-flight logins are owned through compare-and-swap rows; a start on a project another member runs is refused with `409`; adoption of a dead member's run is conditioned on the row it read | A member paused past its TTL whose run was adopted meanwhile keeps streaming it until its next ownership check — a few seconds after it resumes — then lets it go without settling it |
| **D**enial of service | A member dies holding runs, agents and logins | Survivors adopt runs whose workloads outlived it — taking over their secret leases and restoring the git-proxy, Kubernetes-monitor and egress sessions those feed (`TestAdoptedRunTakesOverItsLease`, `TestAdoptedRunsSessionsAreRestored`) — agents reconnect to them, and a new leader takes the exactly-once duties | Host-executor runs and in-flight logins of the dead member are lost. Its proxy sessions come back only with what they stand on — an adopted run's, a device workspace's pinned session (`TestAWorkspaceSessionSurvivesARestart`), a CI relay session at the job's next call (`TestCI_SessionSurvivesAHubRestart`); a Kubernetes Pod's workspace session and any unrecorded session are lost, and a restored egress session is served only by the adopter's own listener. Rate limits and connection caps are per member, so N members admit N times the per-address rate |

---

## Deployment-level threats

| Threat | Mitigation | Residual risk |
| --- | --- | --- |
| Hub installed with authentication switched off | The Helm chart refuses to render a release with no secret source, or one whose generated Secret has neither SSO nor a dashboard token, and CI asserts each guard-rail refusal | Only applies to the chart, and only to a Secret it generates: an `existingSecret` without `CLOOP_UI_TOKEN`, with OIDC off, renders an open hub. A hand-written config can still do this |
| Hub image runs as root or with a writable rootfs | Distroless `nonroot` (65532), CI asserts the image user and boots it `--read-only --cap-drop ALL --security-opt no-new-privileges` | — |
| Dashboard exposed unauthenticated | CI asserts unauthenticated `/api/state` returns 401 on the booted image | — |
| `hub.env` (sealing key, UI token) leaked | Written 0600 by `cloop hub bootstrap`, CI asserts the mode; never committed | Anyone who can read it can unseal every stored secret. Back it up separately from the database, and never together with it |
| Sealing key lost | — | **Unrecoverable.** Every sealed secret becomes permanently unopenable. See [key rotation](../operations/runbook.md#key-rotation) |
| State database corrupted or lost | Hot backup (`cloop db backup`) with a SHA-256 sidecar; `cloop db verify`; restore takes a pre-restore copy first | Backups contain sealed secrets — same handling as the database itself |
| Shared PVC corrupts SQLite | Replicas share the volume only on one node: the chart adds a required podAffinity term pinning them to the node holding the `ReadWriteOnce` volume, and refuses replicas without persistence or with `ReadWriteOncePod` | Nothing stops an operator from mounting the same volume on another node out of band, or from removing the affinity term by editing the Deployment |

---

## Out of scope

- **Kernel and hypervisor vulnerabilities.** Container isolation is namespaces
  and cgroups, not a security boundary against a kernel exploit. A
  [Kata sandbox](../guides/kata.md) changes *which* kernel that is — the guest's
  — and adds a hypervisor escape to the chain; it does not put either kernel in
  scope for this document.
- **Malicious LLM provider.** The provider sees prompts, which include task
  context and code excerpts. Treat that as a data-handling decision made when
  choosing a provider.
- **Physical and supply-chain compromise** of the hub host or the images.
- **What the workload does with credentials it legitimately holds.** Grants
  bound the blast radius; they do not constrain intent.
- **Content sent to a destination the policy allows.** The filter decides
  whether a packet leaves, not what is in it, and the proxy does not terminate
  TLS. A sandbox permitted to reach `api.github.com` can push whatever it likes
  there. Byte quotas bound the volume; nothing bounds the meaning.
- **Whether the kernel or the CNI honours the policy that was installed.**
  `nft -f` commits or fails, so the container path is verifiable from an exit
  status. A `NetworkPolicy` is not: cloop cannot tell from the API whether the
  cluster's CNI implements one.
- **Layer 2 and the physical network.** The filter matches destination
  addresses. ARP, DHCP and anything else that never acquires an IP destination
  are outside what it expresses, as is a network the operator attached the host
  to.

---

## See also

- [Security model](model.md) — boundaries and the guarantee → test table
- [Executor architecture](../architecture/executors.md)
- [Secret and egress grants](../guides/secrets.md)
- [Operator runbook](../operations/runbook.md)
