# Granting secrets and egress

How to give a sandbox exactly the GitHub access, cluster access, or Internet
access it needs — and nothing else — for exactly as long as it needs it.

Every command and every output block below was produced by running the real
binary. Copy them.

- [The model](#the-model)
- [Minting a secret](#minting-a-secret)
- [Granting it](#granting-it)
- [GitHub repositories and PATs](#github-repositories-and-pats)
- [Granting a PAT for workspace provisioning](#granting-a-pat-for-workspace-provisioning)
- [Kubeconfig](#kubeconfig)
- [Container registries](#container-registries)
- [Environment secrets](#environment-secrets)
- [Egress leases](#egress-leases)
- [Inspecting, debugging, revoking](#inspecting-debugging-revoking)
- [Choosing TTLs](#choosing-ttls)

---

## The model

Three nouns, and the distinction between them is the whole design:

| | What it is | Lifetime |
| --- | --- | --- |
| **Secret** | the credential itself, sealed with AES-256-GCM under its own per-row data key. Never leaves the broker in plaintext except inside a Material | until deleted |
| **Grant** | who may use it, narrowed by kind-specific constraints, until when | `--ttl`, default 24 h |
| **Lease** | a short-lived, *minimised* materialisation of every grant matching one (executor, project) | ≤ 15 min |

Executors receive leases. They never receive the store. That is why revoking a
grant takes effect within one lease period rather than at the grant's expiry:
the executor must come back and ask again, and the answer is recomputed from
current grants each time.

**Minimisation is the point.** For `kubeconfig`, `registry` and `env`, the
broker *rewrites the payload* before delivery — a narrower credential cannot be
widened by whoever holds it. `github_pat` and `github_app` are enforced at the
point of use instead, because GitHub has no API to narrow an already-issued
token. `egress_proxy`'s allowlist is enforced by the executor's network policy.
[The security model](../security/model.md#what-is-not-mitigated) is explicit
about which is which; do not mistake one for the other.

Everything fails closed. An unparseable constraint, an unsatisfiable one, an
expired or revoked grant, or a payload that minimises to nothing all produce a
denial and an audit row — never a wider credential.

---

## Minting a secret

```
cloop secret mint <name> --kind <kind> [--file <path> | --value <literal>]
```

| Kind | Payload |
| --- | --- |
| `github_pat` | a GitHub personal access token |
| `github_app` | GitHub App installation JSON (`app_id`, `installation_id`, `private_key`) |
| `kubeconfig` | a kubeconfig YAML document |
| `registry` | docker `config.json`, or `user:password` |
| `env` | one or more environment variables |
| `egress_proxy` | an outbound proxy endpoint, credentials optional |

Prefer **stdin** or `--file`. `--value` puts the credential in your shell history
and in the host process table, and the flag's own help text says so:

```console
$ echo 'ghp_examplesecrettoken' | cloop secret mint deploy-pat --kind github_pat
✓ minted deploy-pat (github_pat) as sec_56315798b775a67cad36ad43
  no grant yet — nothing can use it until you run 'cloop secret grant'
```

A minted secret is inert. Nothing can reach it until it is granted.

> Already using the flat `.cloop/secrets.enc` store? `cloop secret migrate`
> imports those entries into the broker. The legacy `cloop secret set/get/list`
> commands still work during the transition, but they hand *every* secret to
> *every* workload — the thing the broker exists to stop.

---

## Granting it

```
cloop secret grant <secret> --to <subject> [constraints] [--ttl 24h]
```

**Subjects** — who the grant applies to:

| Form | Matches |
| --- | --- |
| `project:/srv/app` | that project path exactly (canonicalised; `/srv/app-staging` does **not** match) |
| `executor:edge-01` | that executor id exactly |
| `label:region=eu,gpu=true` | executors carrying **all** of those labels |
| `any` | every requester — legacy imports only |

**Constraint flags**, by kind:

| Flag | Applies to | Meaning |
| --- | --- | --- |
| `--repos` | `github_pat`, `github_app` | owner/repo globs — **required** (`--repos '*'` to opt out explicitly) |
| `--permissions` | `github_pat`, `github_app` | e.g. `contents:read,pull_requests:write` |
| `--contexts` | `kubeconfig` | context allowlist |
| `--namespaces` | `kubeconfig` | namespace allowlist — at least one of contexts/namespaces required |
| `--registries` | `registry` | registry allowlist — required |
| `--env-keys` | `env` | key allowlist; omit to deliver every key in the secret |
| `--hosts` | `egress_proxy` | host allowlist — required |

`--scope` is a grouping label for operators and carries **no** authority.

---

## GitHub repositories and PATs

```console
$ cloop secret grant deploy-pat \
    --to project:/srv/app \
    --repos 'myorg/*' \
    --permissions 'contents:read' \
    --ttl 24h
✓ granted deploy-pat to project:/srv/app
  grant:       grant_8ce0add1fec2ed4fa00c3a23
  constraints: repos=myorg/* perms=contents:read
  expires:     2026-08-23T09:50:59Z (in 24h0m0s)
```

**Pattern rules.** `myorg/*` matches every repo directly in the org and does not
cross a `/` — `myorg/team/tool` is refused. `myorg/tool` is exact, not a prefix,
so `myorg/toolkit` is refused. `*` and `*/*` mean everything. Matching is
case-insensitive, because GitHub names are.

### What the sandbox actually gets

```
files:  github-token            0600   the raw token
        git-credential-cloop    0700   a POSIX shell credential helper
        gitconfig               0600   installs the helper, sets credential.useHttpPath
env:    GIT_CONFIG_GLOBAL=<lease dir>/gitconfig
        CLOOP_GITHUB_REPO_ALLOWLIST=myorg/*
        CLOOP_GITHUB_PERMISSIONS=contents:read
```

Note what is **absent**: `GITHUB_TOKEN` and `GH_TOKEN`. A bare token is unscoped
by construction — every tool in the sandbox would read it and reach every repo
the PAT can. So the token is exported bare *only* when the allowlist is
explicitly `--repos '*'`. For any narrower grant, the credential helper is the
only delivery path.

The helper is the enforcement point, so it is strict about it: it answers only
`get`, only for `https`, only for host `github.com` exactly (a lookalike like
`github.com.evil.test` gets nothing), only for a single-slash `owner/repo` path,
and only when that path matches the allowlist. No path in the request — which is
what happens when `credential.useHttpPath` is off — means no answer. All of that
is executed against `/bin/sh` in `pkg/secretbroker/githubpat_test.go`, not
inspected as text.

The result: `git clone`, `git push` and `gh` inside `myorg/*` work normally, and
the same commands against `otherorg/private` fail to authenticate.

**`github_app`** is minted and granted identically — `--kind github_app` with an
installation JSON payload — and is constrained by the same `--repos` /
`--permissions` flags.

---

## Granting a PAT for workspace provisioning

Everything above is about what a *running* task can reach. This section is about
something that happens earlier: on an executor that does not share the hub's
filesystem — a Kubernetes Pod, an enrolled device — the project's source tree
has to be **fetched before the harness starts**. That fetch needs a credential
too, and it is the same `github_pat` secret with a different delivery.

The difference matters when you are debugging one. The in-sandbox delivery is a
credential *helper* in a lease directory, materialised for the task. The
workspace fetch happens before any of that exists: it runs in a Kubernetes init
container or as a pre-step on the device, and the token reaches exactly one
`git fetch` process and nothing else — never the harness, never a file, never an
argv. See
[Workspace provisioning](../architecture/executors.md#workspace-provisioning).

End to end, for a project bound to the executor `k8s-prod`:

```console
$ echo 'ghp_examplesecrettoken' | cloop secret mint workspace-pat --kind github_pat
✓ minted workspace-pat (github_pat) as sec_3b62fbde8397949474cda945
  no grant yet — nothing can use it until you run 'cloop secret grant'

$ cloop secret grant workspace-pat \
    --to executor:k8s-prod \
    --repos 'acme/tool' \
    --ttl 24h
✓ granted workspace-pat to executor:k8s-prod
  grant:       grant_a3490558e772e0774814cdd7
  constraints: repos=acme/tool
  expires:     2026-08-23T17:41:04Z (in 24h0m0s)
```

Four things about that command are load-bearing:

- **The subject is the executor**, not the project. Either works — the grant is
  matched against a requester carrying both the executor id and the project path
  — but the executor is the honest description of what is happening: a machine
  is being authorised to fetch a repository. `label:` subjects do **not** work
  on this path.
- **`--repos` must admit the repository being cloned**, matched as `owner/name`
  against the same globs documented above. This is the check that keeps a
  workspace fetch inside its grant.
- **The remote must be an `https://` URL of the shape `owner/name`.** cloop
  rewrites the scp form (`git@github.com:acme/tool.git`) and `ssh://` remotes
  automatically; `http://`, `git://` and local paths are refused, because a
  brokered token over cleartext is a published token and ssh is not something
  the broker can lease. A URL that is not `owner/name` — a GitLab subgroup, say
  — cannot be matched against a repository allowlist at all, so it is fetched
  anonymously rather than refused: no grant could ever have authorised it.
- **No `--permissions` is required.** The fetch is a read, and GitHub enforces
  whatever the PAT itself carries. Setting it is still worth doing, because it
  is recorded in the grant and shows up in the audit trail.

Nothing else changes. The hub picks the grant up on the next run, records only
its *name* in the dispatched workload, and leases the material for the length of
one fetch.

### When it is missing

The run does not start, and it does not start *by name*. The refusal is an HTTP
409 in the run panel (`workspace_grant_missing`) and this on a terminal:

```
executor: cannot provision the workspace for /srv/acme on executor k8s-prod: no
active GitHub grant is issued to executor k8s-prod for this project, so
acme/tool cannot be fetched — grant one with: cloop secret grant
<github-pat-secret> --to executor:k8s-prod --repos acme/tool
```

That is the whole point of the error being typed rather than a string: the
alternative it replaces is a harness that starts in an empty directory and
reports confidently on code it never read.

A grant that exists but *excludes* the repository reads differently — "grant
workspace-pat is issued to this executor but its allowlist excludes repository
acme/tool" — because the fixes are different. One is `cloop secret grant`, the
other is widening `--repos` on the grant you already have; an operator told the
wrong one goes looking in the wrong place.

Two more shapes of the same failure:

| Message names | What it means |
| --- | --- |
| "the project has no origin remote" / "is a local path" | the project is not fetchable at all. Give it an https remote, or bind it to an executor that shares this host's filesystem |
| "cannot materialise a source tree" at *placement* | the executor cannot fetch — a device with no `git`, or an agent below protocol v3. No credential is involved; upgrade the agent or move the project |

`cloop secret lease --project /srv/acme --executor k8s-prod` is the fastest way
to confirm the grant is being seen at all: if `workspace-pat` is not in that
output, the workspace fetch will not see it either.

---

## Kubeconfig

```console
$ cloop secret mint prod-kube --kind kubeconfig --file ~/.kube/config
✓ minted prod-kube (kubeconfig) as sec_382c3ca8e0866696a8c60727
  no grant yet — nothing can use it until you run 'cloop secret grant'

$ cloop secret grant prod-kube \
    --to project:/srv/app \
    --contexts prod \
    --namespaces team-a \
    --ttl 12h
✓ granted prod-kube to project:/srv/app
  grant:       grant_187bd292e8f8da691fa698ea
  constraints: ns=team-a ctx=prod
  expires:     2026-08-22T21:51:12Z (in 12h0m0s)
```

This is the strongest of the guarantees, because the document is rewritten
before it is delivered:

1. only contexts in `--contexts` survive;
2. each survivor is pinned to an allowed namespace — if its current namespace is
   already allowed it is kept, otherwise the first concrete (non-glob) allowed
   namespace is pinned, and if there is no concrete one the context is dropped;
3. clusters and users no longer referenced by a surviving context are **removed
   entirely**, credentials included;
4. `current-context` is repointed if it was dropped.

A workload granted the `prod` context receives a kubeconfig that contains no
server address and no token for `staging`. It cannot reach a cluster it was not
granted, regardless of what it does with the file.

Delivered as:

```
files:  kubeconfig   0600
env:    KUBECONFIG=<lease dir>/kubeconfig
        CLOOP_K8S_NAMESPACE=team-a
        CLOOP_K8S_ALLOWED_NAMESPACES=team-a
```

---

## Container registries

```console
$ cloop secret mint ghcr-login --kind registry --file ~/.docker/config.json
$ cloop secret grant ghcr-login --to label:region=eu --registries ghcr.io --ttl 24h
```

The docker config is filtered to the allowed registries; auth entries for
everything else are stripped. A `user:password` payload is wrapped into a
`config.json` for the first allowed registry. Delivered as `DOCKER_CONFIG`
pointing at the lease directory.

---

## Environment secrets

```console
$ printf 'API_KEY=abc\nWEBHOOK_SECRET=def\n' | cloop secret mint app-env --kind env
$ cloop secret grant app-env --to project:/srv/app --env-keys API_KEY --ttl 8h
```

Only the allowlisted keys are set in the workload's environment; the rest are
dropped. Omitting `--env-keys` delivers every key in the secret — which is fine
when the secret was minted narrow in the first place.

---

## Egress leases

A sandbox runs with `--network=none`. `cloop egress` is how it gets out, and
`egress_proxy` is the fourth grantable resource type.

```console
$ cloop egress grant \
    --to project:/srv/app \
    --hosts 'api.github.com' --hosts '*.pypi.org' \
    --ports 443 \
    --max-down 500m \
    --session-ttl 30m \
    --ttl 8h
✓ granted egress egress_b9c92d36cdec6a598e1bd797
  to      project:/srv/app
  policy  hosts=*.pypi.org|api.github.com ports=443 methods=* down<=500m
  expires Sat, 22 Aug 2026 17:51:12 UTC
  private, loopback, and metadata destinations remain blocked
```

| Flag | Default | Notes |
| --- | --- | --- |
| `--hosts` | — | `api.example.com`, `*.example.com` (subdomains only, **not** the apex), or `'*'`. No implicit wildcard |
| `--cidrs` | — | destination IP prefixes; **the only way to reach a private range** |
| `--ports` | `80,443` | destination port allowlist |
| `--methods` | `*` | plain-HTTP methods only — CONNECT tunnels are opaque |
| `--max-up` / `--max-down` | unlimited | per-session byte quota (`100m`, `2g`) |
| `--session-ttl` | `15m` | one redeemed proxy session; hard ceiling 4 h |
| `--ttl` | `24h` | the grant itself |

At least one of `--hosts` or `--cidrs` is required.

**Private ranges are blocked unless you name them.** Loopback, RFC1918 and
link-local — including cloud metadata at `169.254.169.254` — are refused even
under `--hosts '*'`. Reaching them takes an explicit CIDR, which is a deliberate
speed bump on the SSRF path:

```console
$ cloop egress grant --to label:region=eu --cidrs '10.20.0.0/16' --ports 5432 --session-ttl 30m
```

**What the proxy enforces**, before the first byte leaves: host, port and method;
the destination name resolved **exactly once** with every resolved address
policy-checked and the dial going to the checked literal (so a DNS answer that
changes between check and dial cannot redirect the connection); private-range
blocking; byte quotas cut mid-stream; and the session TTL applied to *open*
tunnels, not just to new ones.

What it does not enforce: anything inside a CONNECT tunnel. cloop holds no key
for the origin, so it accounts bytes, not content.

The sandbox receives `HTTPS_PROXY`/`HTTP_PROXY` (and the lowercase spellings)
pointing at a session-scoped endpoint, plus `CLOOP_EGRESS_ALLOW` and an
`egress-allow.txt` file. The session token is single-use, and only its SHA-256 is
stored — a dump of the control plane does not yield a usable proxy credential.

### Testing a grant without starting a sandbox

```console
$ cloop egress test https://api.github.com/rate_limit
$ cloop egress test https://internal.example.com --to label:region=eu --timeout 10s
```

This redeems a real session and issues the request through the same code path a
container hits, so a pass means the policy genuinely allows it.

---

## Inspecting, debugging, revoking

```console
$ cloop secret grants
GRANT                            SECRET             KIND          SUBJECT                  EXPIRES    CONSTRAINTS
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────
grant_8ce0add1fec2ed4fa00c3a23   deploy-pat         github_pat    project:/srv/app         24h0m0s    repos=myorg/* perms=contents:read

1 grant(s)
```

`--subject`, `--secret` and `--all` (include expired and revoked) filter it.

**"Why isn't my token arriving?"** — dry-run the lease. It shows exactly what an
executor would receive, allowlists and file names only, never payloads:

```console
$ cloop secret lease --project /srv/app --executor edge-01
1 material(s), lease expires 2026-08-22T10:05:59Z

  deploy-pat (github_pat)
    grant:       grant_8ce0add1fec2ed4fa00c3a23
    constraints: repos=myorg/* perms=contents:read
    delivers:    github repos: myorg/* (helper-scoped=true)
    env:         CLOOP_GITHUB_PERMISSIONS, CLOOP_GITHUB_REPO_ALLOWLIST
    files:       git-credential-cloop, gitconfig, github-token
```

`helper-scoped=true` confirms no bare `GITHUB_TOKEN` was exported.

**Revoking:**

```console
$ cloop secret revoke grant_8ce0add1fec2ed4fa00c3a23
$ cloop egress revoke egress_b9c92d36cdec6a598e1bd797
$ cloop egress list --all
```

The two differ, and the difference matters during an incident:

- **Secret grants** stop being honoured at the next lease or renewal. Material
  already materialised is taken back by revoking the *lease* (below), not the
  grant.
- **Egress grants** are cut immediately: every live session under the grant is
  closed at the proxy, mid-tunnel.

Revoking an already-revoked grant succeeds. Every grant, revoke and lease
decision is audited with actor, subject, constraints and reason — and never with
material ([`TestSecretBrokerDecisionsNeverCarryMaterial`](../security/model.md#the-guarantee--test-table)).

---

## Revoking a lease from a running task

Revoking a *grant* changes what the next lease will contain. Revoking a *lease*
takes material back from a task that is already running:

```console
$ curl -X POST https://cloop.example.com/api/leases/lease_8ce0add1/revoke \
    -H "Authorization: Bearer $CLOOP_TOKEN" \
    -d '{"action":"scrub","reason":"PAT rotated"}'
```

or press **Revoke** in the Secrets panel's *Live leases* table. The hub wipes
its own copy and pushes a `revoke` frame to every executor holding the lease;
each one scrubs the material and acknowledges.

### What a scrub actually reaches

This is the part to read before an incident rather than during one. A scrub is
three different guarantees with three different strengths, and the API reports
which one you got rather than flattening them into "revoked":

| Material | Effect of a scrub | Strength |
| --- | --- | --- |
| Credential **files** (kubeconfig, the git credential helper's token file, registry auth) | zeroed and unlinked on the device | **Strong** — the next read fails |
| **Egress** allowlist entries | dropped at the proxy and on the agent | **Strong** — the next connection is refused |
| Environment **variables** | dropped from the agent's memory, so they are never re-injected on a restart, resume, or failover | **Weak** — the running process already has its own copy |

The weak case is not a bug that can be fixed. A process is handed its
environment by the kernel at `exec` time; nothing outside it can reach into
that memory afterwards. This is why cloop's GitHub delivery uses a credential
*helper* reading a token *file* rather than exporting a bare `GITHUB_TOKEN`
(see [What the sandbox actually gets](#what-the-sandbox-actually-gets)) — it
puts the PAT in the column that can actually be revoked.

When the credential itself is compromised rather than merely over-granted, use
`{"action":"kill"}`. The agent scrubs and then terminates every task holding
the lease: `SIGTERM`, then `SIGKILL` five seconds later so a harness that traps
the signal cannot outlive the revocation.

### When the agent is unreachable

**A revocation reaches a device only if the device is reachable.** The response
and the panel report one of four states, and only the first means the material
is gone:

| State | Meaning |
| --- | --- |
| `revoked` | every holder acknowledged; the scrub is done |
| `revoke_pending` | the frame is in flight |
| `unreachable` | at least one holder is offline. **The credential is still on that machine.** The revocation is queued and replayed the moment it reconnects |
| `failed` | a holder answered with an error; read the per-executor detail |

The aggregate state is the *worst* holder's, not the best. Three devices out of
four is not a revocation.

If you see `unreachable` and the credential is compromised, revoke it at the
source — rotate the PAT at GitHub, rotate the kubeconfig's credentials — because
that is the only action that does not depend on a machine you cannot talk to.

`not revocable` in the panel means a holder is running an agent older than
protocol v2 and has no `revoke` frame to honour. The hub refuses to *place* new
revocable material on such an agent, so this only appears for a device
downgraded after a placement. Fix it with
`cloop executor agent install --upgrade`.

### The three triggers

Revocation is driven from three places, all through the same path:

1. **Explicit** — the Secrets panel or `POST /api/leases/{id}/revoke`.
2. **TTL expiry** — a janitor sweeps live agent sessions once a minute and
   scrubs leases whose TTL has lapsed. Before this existed, `Lease.Expired` was
   consulted only by the caller that *minted* the lease, so a fifteen-minute
   credential handed to a three-hour task simply stayed there for three hours.
3. **Cordon and drain** — taking a device out of rotation scrubs everything it
   is holding. It scrubs rather than kills, because draining explicitly waits
   for in-flight work to finish and killing it would contradict the operation
   you asked for.

Each step is audited as `lease.revoke_sent`, then `lease.revoke_acked` or
`lease.revoke_failed`, with the lease and executor IDs and how long the ack
took. All three exist because a revocation is not one event: it is sent, and
then it either lands or it does not — possibly minutes later, when an offline
device reconnects. Collapsing them into one row would make the trail claim a
credential was withdrawn at a moment when it demonstrably still worked.

---

## The Secrets panel

Everything above is also reachable from the dashboard's global **Secrets** tab,
which is the surface a hosted operator has when they do not have a shell on the
hub. Three tables, matching the three concepts in [The model](#the-model):

- **Stored secrets** — name, kind, fingerprint, and how many grants point at
  each. **+ Secret** stores one.
- **Grants** — both brokers in one list, with the full allowlist rendered per
  row and a live countdown. **+ Grant** opens a per-kind wizard: repository
  allowlist and permission subset for a PAT, context and namespace for a
  kubeconfig, host allowlist with byte quotas for egress, registry or env-key
  allowlist for the rest. The wizard offers only secrets matching the chosen
  kind, and there is no "allow everything" default — an empty allowlist is
  rejected by the same `Constraints.ValidateFor` the CLI goes through.
- **Live leases** — what is outstanding *right now*: which executor, which
  project, which credentials, and how long is left. **Revoke** wipes that
  workload's credential directory immediately instead of waiting out the lease.

Each row links into the [Audit panel](../security/model.md) filtered to that
secret or grant, so "who granted this, and when" is one click from the grant
itself.

### What it will not show you

No endpoint behind this panel returns secret material or a decrypted lease
token — not on a read, not in the response to a create, not in an error
message. What a row carries instead is a **fingerprint**: `sha256:` over the
*sealed* record, truncated to 16 hex characters.

That is a deliberate trade. A digest of the plaintext would let you compare two
secrets for equality, and would also hand anyone who can read the endpoint an
offline oracle to test guesses against — fatal for the low-entropy payloads the
store also holds (a registry password, an env value). So the fingerprint
identifies the stored record, not the value: storing the same credential twice
yields two different fingerprints. Use it to confirm a rotation changed
something, not to confirm two secrets match.

`TestSecretsAPIRoutesNeverDiscloseMaterial` seeds known plaintext of every kind
and drives every route — reads, writes, and the error paths that are holding a
credential when they build their message — asserting the canary appears in none
of them, in any encoding.

### Who can see it

The tab is hidden, and every route behind it refused, below **maintainer**:

| Route | Permission |
| --- | --- |
| `GET`/`POST` `/api/secrets`, `/api/grants`, `GET /api/leases` | `secret.grant` |
| `DELETE /api/secrets/{id}`, `DELETE /api/grants/{id}`, `POST /api/leases/{id}/revoke` | `secret.revoke` |

Reads sit at `secret.grant` rather than `project.read` on purpose: the list of
which credentials exist, which executor holds them, and what each may reach is
reconnaissance, and a role that cannot broker access has no reason to enumerate
it. Being able to *spend* a credential — which an operator can, by starting a
run — is not the same as being able to *enumerate* the fleet's credentials.

Every create and revoke lands in the audit trail under the operator's OIDC
identity, not under `ui`. A lease revoked from the panel writes a second row
naming the person who pressed the button: the broker's own release event names
the executor, which does not answer "who took this away".

---

## Choosing TTLs

| | Default | Ceiling | Guidance |
| --- | --- | --- | --- |
| Secret grant `--ttl` | 24 h | — | match the work, not the calendar. A one-off migration is `--ttl 2h` |
| Lease | 15 min | 15 min | not configurable per grant; swept off live agents within a minute of lapsing |
| Egress grant `--ttl` | 24 h | — | as above |
| Egress `--session-ttl` | 15 min | 4 h | longer sessions mean revocation lands later |
| Enrollment token `--ttl` | 15 min | 24 h | it is a bearer secret in transit — keep it short |

The lease TTL is the number to reason about when nobody is watching: an
executor holding a lapsed lease has it swept within a minute of expiry, so the
TTL plus the janitor interval bounds how long unattended material stays live.
When someone *is* watching, revoke the lease directly — that lands in one round
trip rather than at the end of the TTL. Either way, an unreachable agent is
bounded by neither; see
[When the agent is unreachable](#when-the-agent-is-unreachable).

Materials are written into a 0700 tmpfs directory (`/dev/shm` where available),
zeroed and removed when the workload exits.

---

## See also

- [Security model](../security/model.md) — what each guarantee is worth
- [Threat model](../security/threat-model.md) — SSRF, exfiltration, revocation lag
- [Executor architecture](../architecture/executors.md) — where a lease is applied
- [Operator runbook](../operations/runbook.md#key-rotation) — rotating the sealing key online with `cloop hub key rotate`
