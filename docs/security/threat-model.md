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
| **S**poofing | Stolen session cookie replayed | `Secure` + `SameSite=Strict` under TLS; session TTL from `ui.oidc.session_ttl_hours` | No device binding and no server-side revocation list — a stolen cookie is valid until its TTL expires |
| **T**ampering | Request forgery from another origin | `SameSite=Strict` on the session cookie; `wsOriginAllowed` refuses cross-origin WebSocket upgrades (`TestHubRejectsCrossOriginUpgrade`) | Deployments that must set `SameSite=Lax` (plaintext loopback) rely on origin checks alone |
| **T**ampering | Downgrade or MITM on the wire | TLS 1.2 minimum, ECDHE+AEAD suites only, server cipher preference | The hub does not emit HSTS itself; set it at the terminating proxy |
| **R**epudiation | User denies making a privileged change | Every privileged allow *and* deny is written to a SHA-256 hash-chained audit trail with actor identity | Chain proves *tampering*, not *deletion of the tail*: truncating the newest rows leaves a shorter valid chain. Export off-box (see the [runbook](../operations/runbook.md#audit-chain-verification)) |
| **I**nformation disclosure | Dashboard leaks another tenant's project | Every route declares a `Scope`; project-scoped routes resolve the project and re-check visibility (`requireVisibleProject`) | Scoping is per-route; a new route that forgets `Scope` is caught by `routeSpec.validate()` only for the *permission*, not for the scope |
| **I**nformation disclosure | Secrets rendered into the UI or an error | Broker never returns plaintext outside a `Material`; error paths and audit rows are redacted (`TestBrokeredMaterialIsNeverDisclosed`, `TestBrokerErrorsDoNotEchoCredentials`) | Task **output** is not redacted — a workload that echoes its own token puts it on the dashboard |
| **D**enial of service | Request flood or connection exhaustion | Per-IP token-bucket rate limiting; WebSocket connections bounded per-IP and globally; `/healthz` and `/readyz` bypass auth and rate limiting so probes never lock out an operator | A single tenant can still saturate the executor fleet — there is no per-tenant concurrency quota |
| **E**levation of privilege | Viewer performs an operator action | Deny by default: `oidc.default_role: none`; permission declared per route in `routeTable()`, enforced by `gate()`/`require()`; a route with no permission fails `validate()` at startup | Role comes from an IdP claim — an IdP that lets users self-assign groups hands out cloop roles |
| **E**levation of privilege | Reach code execution on the hub host | Strict mode plus a whole-module call-graph gate (`TestNoHandlerReachesProcessExecution`) | Five endpoints legitimately touch the host and are *gated*, not removed; with `allow_host_process: true` this row is unmitigated by construction |

---

## ② Hub ↔ remote agent

| STRIDE | Threat | Mitigation | Residual risk |
| --- | --- | --- | --- |
| **S**poofing | Rogue device enrols as an executor | Single-use token, TTL ≤ 24 h (15 min default), HMAC-checked before any DB lookup, redeemed via `UPDATE … WHERE redeemed_at IS NULL` (`TestEnrollmentTokenIsSingleUse`, `TestEnrollmentTokenSurvivesOnlyOneOfManyConcurrentRedemptions`) | The token is a bearer secret in transit to the device. Deliver it over a channel you trust and keep the TTL short |
| **S**poofing | Attacker impersonates the **hub** to a device | Agent-side SPKI pinning (`--pin sha256:…`), verified in a `VerifyPeerCertificate` hook (`TestAgentDialUsesPinnedTLSConfig`); `CheckEndpoint` refuses plaintext to non-loopback | `--insecure-transport` disables this. It exists for tunnels that are already protected; anything else is a downgrade |
| **S**poofing | Credential lifted from a hub database dump | Only SHA-256 hashes of the token and credential are stored | A dump of the *device* yields `~/.cloop/agent.json` in plaintext (0600). Device compromise is device compromise |
| **T**ampering | Frames modified or replayed on the wire | TLS provides integrity and ordering; frames are version-bounded and handle-scoped (`TestFrameVersionIsBounded`, `TestHandleScopedFramesRequireAHandle`) | **No application-layer replay protection** — there is no nonce or sequence MAC. Security here rests entirely on TLS |
| **T**ampering | One agent forges status for another's workload | The session binds to one agent identity; handle-scoped frames are checked against it | — |
| **R**epudiation | Device denies running a workload | Sessions persist executor id, handle, project, task and attempt in `executor_sessions`; failover events go to the audit sink | Output is attested by the agent itself; a compromised agent can lie about what it ran |
| **I**nformation disclosure | Credentials read off the wire | TLS, with the pin binding *which* TLS peer | Plaintext loopback is permitted by design for local development |
| **D**enial of service | Malicious agent exhausts hub memory | Frame size cap enforced before allocation (`TestOversizedFrameIsRejected`, `TestFrameSizeCapIsSane`); decoders fuzzed for panics (`FuzzFrameDecoding`, `FuzzFrameTruncation`) | An enrolled agent can still hold a connection and heartbeat while doing nothing useful; `cordon`/`revoke` are the answer |
| **D**enial of service | Node vanishes mid-task | Three missed heartbeats (~45 s) → `unreachable` → sessions re-placed exactly once via claim-token rotation | If no candidate satisfies the requirements, the task is marked failed-with-retry rather than moved. There is **no failover attempt limit**, so a `Spec` that itself kills nodes could migrate repeatedly |
| **E**levation of privilege | Agent requests credentials beyond its grants | Leases are computed hub-side from grants matching (executor, project); the agent's request cannot widen them | A compromised agent gets everything granted to it — which is the argument for narrow, short-TTL grants |

---

## ③ Hub ↔ container runtime

| STRIDE | Threat | Mitigation | Residual risk |
| --- | --- | --- | --- |
| **S**poofing | Something else talks to the runtime socket | None at this boundary — the socket is unauthenticated by design | Socket access is root-equivalent on the host. Restrict it with filesystem permissions; this boundary protects the *host from workloads*, not the socket from callers |
| **T**ampering | Workload writes outside its workspace | `--read-only` rootfs; only the project directory is bind-mounted; scratch is a `nosuid,nodev` tmpfs (`TestContainerArgvNeverBreaksItsOwnSandbox`) | The project directory itself is writable by design — that is where work happens |
| **T**ampering | Operator config re-opens the sandbox | `ExtraArgs` denylist rejects `--privileged`, `--cap-add`, `--device`, `--security-opt`, `--volume`, `--pid/ipc/uts/cgroupns`, runtime-socket mounts (`TestContainerRejectsSandboxEscapingExtraArgs`) | A denylist enumerates known-bad flags; a novel runtime flag with the same effect would not be listed |
| **R**epudiation | Which container ran what | Labels carry project and task id; handles map to sessions; `cloop executor reap` finds strays | — |
| **I**nformation disclosure | Secrets visible in the host process table | Forwarded as bare `--env NAME`; the runtime reads the value from its own environment (`TestContainerSecretsNeverEnterArgv`) | Values are still visible in the container's `/proc/1/environ` — to the workload, which already holds them |
| **I**nformation disclosure | Workload reads host filesystem | Mount namespace with a single bind mount | A container escape defeats this. Namespaces are not a VM; set [`executors.container.oci_runtime`](../guides/kata.md) to a Kata runtime for genuinely untrusted code — noting that the project bind mount is shared into the guest either way |
| **D**enial of service | Workload exhausts host CPU/RAM/PIDs | `--cpus`, `--memory`, `--pids-limit`, and `--memory-swap` pinned to the memory ceiling so swap cannot be used to exceed it | Disk is not capped by the driver; a workload can fill the project volume |
| **E**levation of privilege | Workload becomes root on the host | Non-root uid derived from the project directory owner (`TestContainerRefusesRootUser`, `TestValidateNonRootUserRejectsRootSpellings`); `--cap-drop=ALL`; `no-new-privileges` blocks setuid escalation | A kernel vulnerability defeats a namespace boundary. A Kata `oci_runtime` moves it to a guest kernel behind a hypervisor; nothing removes it |
| **E**levation of privilege | Workload reaches the host network or another container | `--network=none` by default; host-network spellings rejected (`TestContainerRejectsHostNetworkSpellings`). `executors.container.egress_filter` adds one of two mechanisms: `internal: true` puts the sandbox on a network with no route off the host, or a direct-egress filter installs a default-deny nftables ruleset on the sandbox bridge covering **both** the `forward` and `input` hooks, so destinations belonging to the host are filtered too (`TestHostSideFilterCoversHostBoundServices`) | The filter is **off unless configured**: a bridge network on an unconfigured hub still has unrestricted outbound access, and preflight warns rather than refuses. The network is per executor, so every sandbox that executor starts shares one bridge and one ruleset |
| **E**levation of privilege | Project names a malicious image in `.cloop/sandbox.yaml` | `sandbox.image_policy` — registry/repo allowlist matched on the **parsed** reference, so `evil.example/ghcr.io/x` and `ghcr.io.evil.example/x` are refused; non-ASCII refused as malformed, removing homographs in one rule; optional cosign verification. Denials are audited as `sandbox.image_denied` (`TestProjectSpecCannotEscapeTheImageAllowlist`) | The policy is **off unless configured** — an unconfigured hub allows any image. The shipped Helm chart configures it; a hand-written `config.yaml` must too |
| **E**levation of privilege | Allowed tag repointed between check and pull (TOCTOU) | An accepted tag is resolved to a digest and the digest is what runs; the tag does not survive past the policy check (`TestSandboxImage_PinsTheOverride`, `TestAuthorizePinsAnAcceptedTag`) | An image with no registry digest — built locally, loaded from a tarball — cannot be pinned. It is refused under `require_signature` and warned about otherwise |
| **E**levation of privilege | Signature verification silently skipped | A missing `cosign` binary is a **denial** with an installation diagnostic, never a pass (`TestSignatureRequirementNeverDegradesToASkip`, `TestCosignMissingFailsClosed`) | Verification trusts the cosign binary on the hub's PATH and the keys the operator configured |
| **E**levation of privilege | Unaudited image fetched at task time | `--pull=never` — the image must already be present, so nothing is fetched at task time | Which images are present is the operator's out-of-band `pull`; the policy governs the reference, not who pulled it |

---

## ④ Hub ↔ Kubernetes cluster

| STRIDE | Threat | Mitigation | Residual risk |
| --- | --- | --- | --- |
| **S**poofing | Stolen kubeconfig used elsewhere | Delivered as a lease, held in memory only, released on terminal state; rewritten to contain only allowed contexts and their clusters/users | The credential inside remains a valid cluster credential for its own lifetime — cloop cannot shorten the cluster's token TTL |
| **T**ampering | Workload mutates its own Pod to gain privilege | Role grants `create/get/list/watch/delete` on Pods and `get` on `pods/log`; `update`/`patch` are **denied**, asserted in both directions in CI | — |
| **R**epudiation | Who created this Pod | Pods carry project/task labels; creation flows through the audit trail | Cluster audit logging is the cluster's job |
| **I**nformation disclosure | Env visible to others in the namespace | Documented, not prevented: `Spec.Env` is readable via `get pods` | **Not mitigated by cloop.** Use a dedicated workload namespace with its own RBAC |
| **I**nformation disclosure | Workload reads cluster Secrets | Role denies `get`/`list` on Secrets; Pod sets `automountServiceAccountToken: false`, so the workload holds no cluster credential | — |
| **D**enial of service | Workload never terminates | `activeDeadlineSeconds` (default 7200) plus CPU/memory requests and limits | A tight scheduling loop can still exhaust namespace quota; set a `ResourceQuota` |
| **E**levation of privilege | Workload escapes the Pod | `runAsNonRoot`, read-only rootfs, all capabilities dropped, `seccompProfile: RuntimeDefault`; `executors.kubernetes.runtime_class` puts every Pod on a [Kata node pool](../guides/kata.md#kubernetes) when the cluster has one | Standard container isolation caveats apply to the default runtime. cloop names a RuntimeClass; whether that class is really Kata, and whether the node enforces it, is the cluster's to answer |
| **E**levation of privilege | Project names a malicious image, or a tag a node resolves later | The same `sandbox.image_policy` governs the Pod builder, and the digest is what lands in the container spec (`TestPinnedDigestLandsInTheContainerSpec`, `TestPolicyReachesTheExecutorThatRunsTheImage`) | The control plane cannot read a cluster's image store, so a tag **cannot** be pinned here — only required to arrive pinned. Without `require_digest: true` a kubelet resolves the tag whenever it schedules, and the artifact that runs is not the one anything evaluated. The chart sets it |
| **E**levation of privilege | Workload reaches other cluster services | With `executors.kubernetes.egress_filter` enabled, a `NetworkPolicy` per Pod selecting that Pod alone by its handle-id label, compiled from the same policy the container driver's ruleset is (`TestBothBackendsRefuseTheSameDestinations`); `policyTypes` names `Ingress` with no ingress rules, so inbound is denied too | Off by default, so an unconfigured hub is unchanged: the Pod joins the cluster network and cloud owns the restriction. Even enabled, a `NetworkPolicy` is inert unless the CNI implements one — flannel does not, and the API server stores the object regardless. Reported as a standing `egress-enforcement` preflight warning |

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
| **E**levation of privilege | A host allowlist is relied on for a workload that dials directly | The widening is opt-in (`allow_public_internet`), never inferred from the presence of host patterns, and every rendering of the policy carries a warning naming the patterns and what they became — an nft comment, a `NetworkPolicy` annotation, an `egress-scope` preflight finding | **Unfixable at layer 3.** `*.github.com` is a name and a packet carries an address. The narrow configuration is `internal` mode, where the proxy is the only reachable destination and the host allowlist is enforced inside it |
| **E**levation of privilege | A sandbox reaches the cloud metadata service | `169.254.169.254/32` is dropped by prefix in both the proxy's block set and the compiled filter, ahead of the link-local drop that contains it so the *reason* reaching the audit trail is the specific one. Only a CIDR that names the address exactly waives it (`TestMetadataStaysBlockedUnderAnAcceptedGrant`) | A grant of `169.254.169.254/32` is a real hole by intent, and is meant to be a sentence somebody wrote |
| **S**poofing | A blocked address written in a form the filter does not recognise | Both layers see through the v4-in-v6 spellings; the filter drops the NAT64, 6to4, IPv4-translatable and IPv4-compatible prefixes wholesale because a packet filter cannot unwrap an embedded address (`TestFilterAgreesWithBrokerOnNamedAddresses`, `TestFilterAgreesWithBrokerOnASweep`) | The wholesale drop is stricter than the proxy: `64:ff9b::8.8.8.8` is a public address the proxy allows and the filter refuses |
| **T**ampering | Operator input injects a rule into the host's firewall | Table, chain and interface names are validated against a grammar narrower than nft's; rule comments — built partly from operator-supplied CIDRs — have every character that could end the string or the line replaced, and are truncated on a rune boundary (`TestCommentInjectionCannotEscapeTheString`, `TestRenderNftablesRefusesUnsafeNames`) | The ruleset is applied by shelling out to `nft(8)`, so it inherits whatever that binary on the hub's `PATH` is. The path is resolved once at construction, not per apply |
| **D**enial of service | The filter fails to install and the sandbox starts anyway | A failed install fails the `Start`. Producing a working sandbox with none of the requested filtering, silently, is the one outcome worse than refusing to run | An `nft` that is missing, or a control plane without `CAP_NET_ADMIN`, therefore stops `filtered` sandboxes from starting at all. Preflight reports it as `fail` with the two fixes (install nftables and grant the capability, or switch to `internal` mode, which needs neither) |
| **E**levation of privilege | The workload starts before its filter does | The ruleset attaches to the *bridge*, from the host side, and the bridge exists from the moment the runtime creates the network — strictly before any container can join it. The alternative (start it, find its PID, `nsenter`) has a window and is not what the driver does | Applies to the container driver. In Kubernetes the `NetworkPolicy` is created alongside the Pod and the CNI programs it on its own schedule |

---

## Vulnerabilities found while building this

Recorded because a threat model that lists only theoretical threats is less
useful than one that lists the threats that were actually present. All are
fixed and all have a regression test.

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

**The Groq API key was passed on the argv.** `/api/voice` appended a
caller-supplied `--groq-api-key` to the subprocess argv, where
`/proc/<pid>/cmdline` exposes it to every local user for the lifetime of the
child — the same exposure `install_script.go` already refuses for enrolment
tokens. Fixed by passing it in the environment, which `cloop listen` already
reads as `GROQ_API_KEY`; the plumbing appends to the inherited environment
rather than replacing it, since `applyLease` reads a nil `Spec.Env` as
"inherit `os.Environ()`".

---

## Cross-cutting: the secret and egress brokers

| STRIDE | Threat | Mitigation | Residual risk |
| --- | --- | --- | --- |
| **S**poofing | Executor claims another's identity to collect its grants | Subject matching is exact — canonicalised project paths (`/srv/app-staging` does not match `project:/srv/app`), exact executor ids, all-keys label selectors | Label selectors are only as trustworthy as the labels, which are operator-assigned at enrolment |
| **T**ampering | Holder widens a delivered credential | Enforced *by construction* for `kubeconfig`, `registry` and `env`: the payload is rewritten before delivery and a narrower payload cannot be widened | `github_pat` is enforced *at use* by a git credential helper — it binds `git`, not a direct REST call. `github_app` is constrained like a PAT. `egress_proxy` enforcement lives in the executor's network policy |
| **R**epudiation | Who granted this access | Every grant, revoke and lease decision is audited with actor, subject, constraints and reason (`TestSecretBrokerDecisionsNeverCarryMaterial`) | — |
| **I**nformation disclosure | Material lands on disk or in logs | Sealed at rest (AES-256-GCM); materialised into a 0700 tmpfs dir (`/dev/shm` where available); zeroed and removed on exit; never in `Error()` strings or audit rows | Where `/dev/shm` is unavailable the fallback is `os.TempDir()`, which may be disk-backed — hence the explicit zeroing |
| **D**enial of service | Revocation does not take effect | Leases are short (15 min max) and revalidate every grant on renewal; egress revocation tears down **live sessions** immediately | A secret already materialised survives until its lease expires — up to 15 minutes. To cut access instantly, revoke *and* stop the workload |
| **E**levation of privilege | SSRF into the hub's private network | Loopback, RFC1918 and link-local are blocked unless explicitly listed in `--cidrs`; cloud metadata (`169.254.169.254`) requires a CIDR that names it exactly; a `/0`, and any prefix containing the metadata address without naming it, are refused at grant time (`TestWideCIDRsCannotBypassTheBlockSet`) | Granting a private CIDR is a real hole by intent — grant the narrowest prefix and port |
| **E**levation of privilege | DNS rebinding between check and dial | Resolve-once pinning: the name is resolved once, every resolved address is policy-checked, and the dial goes to the checked literal | — |
| **E**levation of privilege | Exfiltration through an allowed host | Per-session byte quotas (`--max-up`, `--max-down`), enforced mid-stream | CONNECT tunnels are opaque — cloop holds no key for the origin, so it sees bytes, not content. `--methods` gates plain HTTP only |

---

## Deployment-level threats

| Threat | Mitigation | Residual risk |
| --- | --- | --- |
| Hub installed with authentication switched off | The Helm chart *refuses* to render a release with neither SSO nor a dashboard token, and CI asserts each guard-rail refusal | Only applies to the chart. A hand-written config can still do this |
| Hub image runs as root or with a writable rootfs | Distroless `nonroot` (65532), CI asserts the image user and boots it `--read-only --cap-drop ALL --security-opt no-new-privileges` | — |
| Dashboard exposed unauthenticated | CI asserts unauthenticated `/api/state` returns 401 on the booted image | — |
| `hub.env` (sealing key, UI token) leaked | Written 0600 by `cloop hub bootstrap`, CI asserts the mode; never committed | Anyone who can read it can unseal every stored secret. Back it up separately from the database, and never together with it |
| Sealing key lost | — | **Unrecoverable.** Every sealed secret becomes permanently unopenable. See [key rotation](../operations/runbook.md#key-rotation) |
| State database corrupted or lost | Hot backup (`cloop db backup`) with a SHA-256 sidecar; `cloop db verify`; restore takes a pre-restore copy first | Backups contain sealed secrets — same handling as the database itself |
| Shared PVC corrupts SQLite | Chart pins `replicaCount: 1` and `ReadWriteOnce`, and refuses configurations that would share the volume | Nothing stops an operator from mounting the same volume elsewhere out of band |

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
