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
| **I**nformation disclosure | Workload reads host filesystem | Mount namespace with a single bind mount | A container escape defeats this. Namespaces are not a VM; use `kubernetes` with a hardened runtime class, or a VM, for genuinely untrusted code |
| **D**enial of service | Workload exhausts host CPU/RAM/PIDs | `--cpus`, `--memory`, `--pids-limit`, and `--memory-swap` pinned to the memory ceiling so swap cannot be used to exceed it | Disk is not capped by the driver; a workload can fill the project volume |
| **E**levation of privilege | Workload becomes root on the host | Non-root uid derived from the project directory owner (`TestContainerRefusesRootUser`, `TestValidateNonRootUserRejectsRootSpellings`); `--cap-drop=ALL`; `no-new-privileges` blocks setuid escalation | Kernel vulnerabilities are out of scope for a namespace boundary |
| **E**levation of privilege | Workload reaches the host network or another container | `--network=none` by default; host-network spellings rejected (`TestContainerRejectsHostNetworkSpellings`); reaching the Internet requires an [egress lease](../guides/secrets.md#egress-leases) | Enabling a bridge network for a project trades this away; the egress broker's proxy is the narrower alternative |
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
| **E**levation of privilege | Workload escapes the Pod | `runAsNonRoot`, read-only rootfs, all capabilities dropped, `seccompProfile: RuntimeDefault` | Standard container isolation caveats. Use a hardened `runtimeClass` (gVisor, Kata) for untrusted code |
| **E**levation of privilege | Project names a malicious image, or a tag a node resolves later | The same `sandbox.image_policy` governs the Pod builder, and the digest is what lands in the container spec (`TestPinnedDigestLandsInTheContainerSpec`, `TestPolicyReachesTheExecutorThatRunsTheImage`) | The control plane cannot read a cluster's image store, so a tag **cannot** be pinned here — only required to arrive pinned. Without `require_digest: true` a kubelet resolves the tag whenever it schedules, and the artifact that runs is not the one anything evaluated. The chart sets it |
| **E**levation of privilege | Workload reaches other cluster services | Pod network; the driver reports `NetworkEgress: true` and does not restrict it | **Not enforced by cloop.** The cluster owns this — apply a default-deny `NetworkPolicy` in the workload namespace |

---

## Cross-cutting: the secret and egress brokers

| STRIDE | Threat | Mitigation | Residual risk |
| --- | --- | --- | --- |
| **S**poofing | Executor claims another's identity to collect its grants | Subject matching is exact — canonicalised project paths (`/srv/app-staging` does not match `project:/srv/app`), exact executor ids, all-keys label selectors | Label selectors are only as trustworthy as the labels, which are operator-assigned at enrolment |
| **T**ampering | Holder widens a delivered credential | Enforced *by construction* for `kubeconfig`, `registry` and `env`: the payload is rewritten before delivery and a narrower payload cannot be widened | `github_pat` is enforced *at use* by a git credential helper — it binds `git`, not a direct REST call. `github_app` is constrained like a PAT. `egress_proxy` enforcement lives in the executor's network policy |
| **R**epudiation | Who granted this access | Every grant, revoke and lease decision is audited with actor, subject, constraints and reason (`TestSecretBrokerDecisionsNeverCarryMaterial`) | — |
| **I**nformation disclosure | Material lands on disk or in logs | Sealed at rest (AES-256-GCM); materialised into a 0700 tmpfs dir (`/dev/shm` where available); zeroed and removed on exit; never in `Error()` strings or audit rows | Where `/dev/shm` is unavailable the fallback is `os.TempDir()`, which may be disk-backed — hence the explicit zeroing |
| **D**enial of service | Revocation does not take effect | Leases are short (15 min max) and revalidate every grant on renewal; egress revocation tears down **live sessions** immediately | A secret already materialised survives until its lease expires — up to 15 minutes. To cut access instantly, revoke *and* stop the workload |
| **E**levation of privilege | SSRF into the hub's private network | Loopback, RFC1918 and link-local are blocked unless explicitly listed in `--cidrs`; cloud metadata (`169.254.169.254`) requires an explicit CIDR grant | Granting a private CIDR is a real hole by intent — grant the narrowest prefix and port |
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
  and cgroups, not a security boundary against a kernel exploit.
- **Malicious LLM provider.** The provider sees prompts, which include task
  context and code excerpts. Treat that as a data-handling decision made when
  choosing a provider.
- **Physical and supply-chain compromise** of the hub host or the images.
- **What the workload does with credentials it legitimately holds.** Grants
  bound the blast radius; they do not constrain intent.

---

## See also

- [Security model](model.md) — boundaries and the guarantee → test table
- [Executor architecture](../architecture/executors.md)
- [Secret and egress grants](../guides/secrets.md)
- [Operator runbook](../operations/runbook.md)
