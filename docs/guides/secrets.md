# Granting secrets and egress

How to give a sandbox exactly the GitHub access, cluster access, or Internet
access it needs — and nothing else — for exactly as long as it needs it.

Every command and every output block below was produced by running the real
binary. Copy them.

- [The model](#the-model)
- [Minting a secret](#minting-a-secret)
- [Granting it](#granting-it)
- [Connecting a GitHub App from the dashboard](#connecting-a-github-app-from-the-dashboard)
- [GitHub repositories and PATs](#github-repositories-and-pats)
- [Granting a PAT for workspace provisioning](#granting-a-pat-for-workspace-provisioning)
- [Kubeconfig](#kubeconfig)
- [Container registries](#container-registries)
- [Environment secrets](#environment-secrets)
- [Local git repositories](#local-git-repositories)
- [Host devices](#host-devices)
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
widened by whoever holds it. `github_app` is narrowed by GitHub itself: the hub
keeps the App's private key and mints a fresh ~1 h installation token scoped to
the grant's repositories and permissions for each lease. `github_pat` is the one
GitHub kind enforced at the point of use instead, because GitHub has no API to
narrow an already-issued token — which is why
[`github_app` is the one to prefer](../security/model.md#github_pat-versus-github_app).
`egress_proxy`'s allowlist is enforced by the executor's network policy.
`local_repo` is minimised by *selection* — only the repositories its allowlist
matches are ever bound, and the bind is read-only unless the grant says
otherwise. [The security model](../security/model.md#what-is-not-mitigated) is
explicit about which is which; do not mistake one for the other.

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
| `github_app` | GitHub App installation JSON: `app_id`, `installation_id`, `private_key`, optional `base_url`. The hub mints short-lived installation tokens from it and never delivers the key. The dashboard [discovers the installation ID for you](#connecting-a-github-app-from-the-dashboard) — [worked example](#github-repositories-and-pats) |
| `kubeconfig` | a kubeconfig YAML document |
| `registry` | docker `config.json`, or `user:password` |
| `env` | one or more environment variables |
| `egress_proxy` | an outbound proxy endpoint, credentials optional |
| `local_repo` | an absolute path **on the hub host** to a directory of git repositories (or to a single repository) |
| `host_device` | an inventory of device nodes on the executor's host, one `name=/dev/path` per line |
| `host_interface` | an inventory of network interfaces on the executor's host, one `name=ifname` per line. Honouring one **moves** the interface into the sandbox, so the executor gives it up for the life of the run — [worked example](#host-network-interfaces) |

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
| `--repos` | `local_repo` | repository *directory-name* globs under the granted root — **required** |
| `--permissions` | `github_pat`, `github_app` | e.g. `contents:read,pull_requests:write` |
| `--contexts` | `kubeconfig` | context allowlist |
| `--namespaces` | `kubeconfig` | namespace allowlist — at least one of contexts/namespaces required |
| `--verbs` | `kubeconfig` | RBAC verb allowlist; omit for read-only (`get,list,watch`). Needs the [access monitor](../architecture/kubernetes-access.md) to be enforced |
| `--registries` | `registry` | registry allowlist — required |
| `--env-keys` | `env` | key allowlist; omit to deliver every key in the secret |
| `--hosts` | `egress_proxy` | host allowlist — required |
| `--devices` | `host_device` | device-*name* globs from the inventory — **required** |
| `--interfaces` | `host_interface` | interface-*name* globs from the inventory — **required** |

`--scope` is a grouping label for operators and carries **no** authority.

One more constraint applies to `local_repo` and `host_device` only:
`--writable`, which is the single constraint that *widens* rather than narrows —
see [Read-only by default](#read-only-by-default) and
[Narrowing is the only direction](#narrowing-is-the-only-direction).

---

## Connecting a GitHub App from the dashboard

The CLI needs an `installation_id`, and GitHub does not give you one. The App's
settings page hands out an App ID and a private key; the installation is created
later, by whoever installs the App on their organisation, and its ID appears
only in the URL of a settings page you may never open.

So the dashboard asks GitHub instead. Under **Settings → GitHub Apps**, paste
the App ID and the PEM and press **Find installations**: the hub signs a
short-lived app JWT, calls `GET /app/installations`, and lists every account the
App is installed on with its type and whether it covers all repositories or a
chosen subset. Pick one and the `github_app` secret is stored with that ID
filled in. Nothing is persisted until you pick — the key is held only for the
length of the dialog.

Then, on a project's **Overview** tab, **Repository Access** lists what that
project may reach and offers the rest. Choosing an App and pressing **List
repositories** enumerates the installation's own inventory, so the names you
tick are ones GitHub has already confirmed the App can see rather than patterns
typed from memory. Pick **Read only** or **Read and write** — which expand to
`contents:read` and to `contents:write` plus `pull_requests:write`, and to
nothing else — and the grant is created against `project:<path>`.

This is the same broker call `cloop secret grant` makes, so a grant created
either way shows up in both places, and `cloop hub audit list` records it
identically.

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
case-insensitive, because GitHub names are. (`local_repo` is the exception: its
patterns match directory names, which on Linux are case-sensitive, so `api` does
not open `API`.)

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

### The helper's limit, and what removes it

Be precise about what the paragraph above buys, because it is less than it
looks. The helper runs **inside the sandbox**, and it reads `github-token`,
which is also inside the sandbox. A workload that ignores git and reads the file
has the whole token. So for a `github_pat` the allowlist is enforced against
*git*, not against the workload — it stops an honest `git clone otherorg/private`
and it does not stop a determined one.

That gap matters most in the case this is usually used for. A personal access
token normally carries `repo` across everything its owner can see, so a user who
grants one to a project is, absent anything further, granting the project that
whole reach.

**Turning on the [git interception proxy](../git-interception-proxy.md) closes
it.** With `executors.git_proxy.enabled: true`, a `github_pat` is delivered
differently: the hub keeps the token and the sandbox gets a proxy session
instead.

```
files:  git-proxy-credential    0600   a session credential, useless off the proxy
        git-credential-cloop    0700   releases it for the proxy host only
        gitconfig               0600   rewrites github.com to the proxy
env:    GIT_CONFIG_GLOBAL=<lease dir>/gitconfig
        CLOOP_GIT_PROXY_URL=https://hub.internal:8443
        CLOOP_GIT_PROXY_SESSION=<session id>
        CLOOP_GIT_PROXY_MODE=read-only
        CLOOP_GITHUB_REPO_ALLOWLIST=myorg/*
```

There is no `github-token`. The allowlist moves from a script the workload can
read around to the network path it cannot avoid, and two things become true that
were not before:

- **The allowlist is enforced.** `myorg/*` is checked by the proxy, outside the
  sandbox, on every request. Reaching `otherorg/private` is a 403 from the proxy
  and an audit row, whatever the workload does with the files it was given.
- **`--permissions` starts meaning something.** A grant that authorises no write
  (`contents:read`, or no `--permissions` at all) yields a session that cannot
  push — even though the PAT behind it can. Deletes are never granted. The hub's
  configured `allowed_refs` is the ceiling, and a grant can only narrow within
  it.

`git clone`, `git push` and submodules keep working unchanged, because the
rewriting is transparent: a remote of `https://github.com/myorg/tool` — or
`git@github.com:myorg/tool` — resolves to the proxy without the workload opting
in. What breaks is `gh` and anything else speaking the GitHub **API**, which is
not git traffic and has no proxy to route through; those need a `github_app`
grant, whose token GitHub itself has already narrowed.

If `executors.git_proxy.enabled` is true and the proxy is not running, a
`github_pat` lease **fails** rather than falling back to writing the token into
the sandbox. A boundary that fails open is not a boundary.

**Those three files have to reach the sandbox for any of this to be true**, and
which executor you are bound to decides how they get there. The hub writes them
to its own disk only for the host-process driver; a container gets a private
per-run tmpfs bind-mounted read-only, a Pod gets a per-run Secret projected
read-only, and an edge device is sent the bytes on the start frame and writes
them itself. An executor that cannot receive files at all — an agent below
protocol v6 — refuses the run with the `secret_files` placement constraint
rather than starting a sandbox that would hold `GIT_CONFIG_GLOBAL` pointing at
nothing and no token behind it. See
[Secret file delivery](../architecture/executors.md#secret-file-delivery).

**`github_app`** is granted with the same `--repos` / `--permissions` flags, but
the payload is a strict JSON document rather than a token, and what the sandbox
receives is not what you stored.

```
$ cat app.json
{
  "app_id": 424242,
  "installation_id": 313131,
  "private_key": "-----BEGIN RSA PRIVATE KEY-----\nMIIEow...\n-----END RSA PRIVATE KEY-----\n"
}

$ cloop secret mint deploy-app --kind github_app --file app.json
✓ minted deploy-app (github_app) as sec_9f14c2e0a7b36d5148e1cc02

$ cloop secret grant deploy-app --to project:/srv/app \
    --repos 'acme/tool' --permissions contents:write --ttl 24h
```

`app_id` and `installation_id` come from the App's settings page; `private_key`
is the PEM the **Generate a private key** button downloads, with its newlines
escaped as `\n` (`jq -Rs` does this). Both IDs must be integers and the key must
parse as RSA — a malformed payload is refused by `cloop secret mint` and by the
dashboard, rather than being stored and failing inside somebody's run. Add
`"base_url": "https://ghe.example.com/api/v3"` for GitHub Enterprise Server.

At lease time the hub signs a nine-minute JWT with that key and exchanges it for
an installation token narrowed to the repositories the grant allows and the
permissions it names. **Only the token is delivered.** The private key never
leaves the hub, the token expires in about an hour, each lease renewal mints a
fresh one and destroys the old, and releasing or revoking calls
`DELETE /installation/token` so the credential dies at GitHub rather than only
on the sandbox's disk. Each destruction is audited as `github_app.token_destroy`
— its own action rather than `secret.revoke`, because it happens on every
ordinary task teardown and would otherwise drown the count of grants an operator
actually withdrew. A DELETE that GitHub refuses is recorded as a **denial**
naming how long the token stays live, which is the row to search for during an
incident.

Two consequences worth knowing before you pick this kind:

- **The hub needs reach to `api.github.com`.** A mint that fails denies the
  grant — there is no fallback to delivering the key, because that fallback is
  the thing this design exists to prevent. An air-gapped hub uses `github_pat`.
- **A grant naming a repository the App is not installed on is refused**, with
  the missing repository named, instead of producing a token that 404s at the
  first clone. `--repos 'acme/*'` is resolved against the installation's actual
  repository list, so the same check covers globs.

[The security model](../security/model.md#github_pat-versus-github_app) has the
side-by-side comparison and says when a PAT is still the right answer.

The [git interception proxy](../git-interception-proxy.md) does **not** change
any of this. It brokers the one repository cloop itself clones and pushes back
to, on the [workspace-provisioning path](#granting-a-pat-for-workspace-provisioning);
a PAT granted to the task is delivered into the sandbox as above whether or not
a proxy is configured.

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

### With the git proxy on, the token does not enter the sandbox at all

A hub with [`executors.git_proxy`](../git-interception-proxy.md) enabled leases
this grant exactly as described above and then keeps the PAT: the sandbox is
given a session token for a proxy the hub runs, and its remote is rewritten to
that proxy. The clone and the write-back push both go through it, and the proxy
refuses any ref update outside `refs/heads/cloop/**`.

Nothing about the grant changes — same `--to executor:…`, same `--repos`, same
matching, same audit rows naming the same grant and repository, because the
proxy's URL keeps the `owner/name` shape the allowlist is matched against. What
changes is that a leaked sandbox now yields a token worth one namespace on one
repository for the rest of its TTL, instead of the PAT.

Two things worth knowing before turning it on: a session lasts
`session_minutes` (60 by default) rather than the length of a run, so a run that
outlives it fails its push; and the sandbox's git must trust the proxy's
certificate, which for a self-signed hub certificate means installing the CA in
the sandbox image. Both are covered in
[operating it](../git-interception-proxy.md#operating-it).

**It does not cover the section above.** A `github_pat` granted for the *task* is
still delivered into the sandbox as a credential helper — that grant exists so
the workload can reach repositories, and the proxy brokers exactly one:
the project's own. The two are separate paths and separate decisions.

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

**Which clusters** is the strongest of the guarantees, because the document is
rewritten before it is delivered:

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

**Which namespaces, and read-only, are a different matter.** Step 2 pins a
namespace into the delivered context, and a `namespace:` in a kubeconfig is only
the value `kubectl` uses when you omit `-n` — `kubectl -n kube-system get
secrets` ignores it. Verbs cannot be written into a kubeconfig at all; the
document carries a credential, and its authority is whatever the cluster's RBAC
grants the user it belongs to.

Both are enforced by the [Kubernetes access monitor](../architecture/kubernetes-access.md),
which runs outside the sandbox and decides every API request before the cluster
credential is attached. Turn it on with `executors.kube_guard.enabled: true`.
Without it, `--namespaces` and `--verbs` are recorded and audited but not
enforced, and the Secrets panel marks such a grant **unguarded**.

Delivered as:

```
files:  kubeconfig   0600
env:    KUBECONFIG=<lease dir>/kubeconfig
        CLOOP_K8S_NAMESPACE=team-a
        CLOOP_K8S_ALLOWED_NAMESPACES=team-a
        CLOOP_K8S_VERBS=get,list,watch
```

With the monitor on, the delivered `kubeconfig` points at the monitor and
carries a short-lived session token instead of the cluster credential, and
`CLOOP_KUBEGUARD_SESSION` names the session so an operator can revoke it.

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

## Local git repositories

Every other kind hands a workload *bytes*. This one hands it **paths**: a
directory on the hub host holding git checkouts, opened to one project as bind
mounts. It is for the developer who has three repositories on the machine the
hub runs on and wants one project to build against them.

It is a grant rather than a
[`.cloop/sandbox.yaml`](../reference/sandbox.md) mount because that file is
repo-committed — it is whatever a pull request says it is — which is exactly why
`mounts.source` there is workspace-relative and cannot name a host path at all.
This kind is the same capability with the trust inverted: a human holding
`secret.grant` names the root, the repositories and the project, out of band. So
it arrives with the properties every other authority here already has — one
subject, a TTL, an audit row naming who opened it, and revocation that lands
within a lease period rather than at the end of the run.

```console
$ cloop secret mint local-src --kind local_repo --value /home/dev/src
✓ minted local-src (local_repo) as sec_8f2cca804195c0b73296b674
  no grant yet — nothing can use it until you run 'cloop secret grant'
```

The payload is an **absolute path on the hub** to a directory containing git
repositories. A root that is itself a repository is accepted too, so the
single-checkout case needs no wrapper directory. `--value` is not a disclosure
risk for once — the payload is a path, not a credential.

The root is stored once and each grant opens a different slice of it to a
different project, which is what "these particular repositories" means when
there are five projects and twenty checkouts:

```console
$ cloop secret grant local-src \
    --to project:/srv/app \
    --repos 'api-service' --repos 'shared-*' \
    --ttl 8h
✓ granted local-src to project:/srv/app
  grant:       grant_dfdcf87b1d4ea6da67bcbba7
  constraints: repos=api-service|shared-*
  expires:     2026-08-23T08:08:36Z (in 8h0m0s)
```

**`--repos` is required, and it is matched differently here than for a PAT.**
The subject is the repository's *directory name* directly under the root, not
`owner/repo`: `api-service` is exact, `shared-*` is a glob, `*` is every
repository under the root. Only **direct children** are considered — a root of
`/home/dev` does not reach a checkout at `/home/dev/.cache/dep/vendor/x`, which
is not what anyone granting "the source tree" is picturing. Entries that are not
git repositories, and entries whose name begins with a dot, are skipped. At most
32 repositories may be opened by one grant; past that the grant has stopped
describing "these repositories" and started describing the machine, and it is
refused rather than truncated.

Omitting it is refused at creation, not at delivery:

```console
$ cloop secret grant local-src --to project:/srv/app
Error: secretbroker: invalid constraint: a local_repo grant needs a repository
allowlist (--repos my-service, or --repos '*' for every repository under the root)
```

So is an allowlist that matches nothing — a lease that delivered an empty
`/repos` would let the harness discover the problem as a missing directory
several minutes in.

### What the sandbox actually gets

Repositories appear under **`/repos`**. The path is fixed rather than
configurable so a harness, a setup script and a README can all name it without
knowing which executor they landed on, and it sits outside `/workspace` because
the workspace is bind-mounted whole — a target underneath it would be shadowed
by that mount on some drivers and not others.

```
mounts: /home/dev/src/api-service   ->  /repos/api-service    read-only
        /home/dev/src/shared-proto  ->  /repos/shared-proto   read-only
env:    CLOOP_LOCAL_REPOS=api-service,shared-proto
        CLOOP_LOCAL_REPO_ROOT=/repos
        CLOOP_LOCAL_REPO_API_SERVICE=/repos/api-service
        CLOOP_LOCAL_REPO_SHARED_PROTO=/repos/shared-proto
```

`CLOOP_LOCAL_REPOS` is the list that stays true whatever the driver does, and it
is the one the broker sets. The path variables are added later, by the caller
holding both the lease and the executor, because *where* the repositories are is
a property of the driver rather than of the grant (see below). A repository whose
name has no unambiguous rendering as a variable name — `my-api` and `my.api`
would both fold to `CLOOP_LOCAL_REPO_MY_API` — gets no convenience variable
rather than one pointing at whichever grant was processed last. It is still
mounted and still listed in `CLOOP_LOCAL_REPOS`.

Dry-run it like any other lease:

```console
$ cloop secret lease --project /srv/app --executor edge-01
1 material(s), lease expires 2026-08-23T00:23:36Z

  local-src (local_repo)
    grant:       grant_dfdcf87b1d4ea6da67bcbba7
    constraints: repos=api-service|shared-*
    delivers:    local repos (read-only): api-service,shared-proto
    env:         CLOOP_LOCAL_REPOS
```

Anything under the root that the allowlist does not match, or that is not a git
repository, is simply absent from that list. Both checks run against this host,
so a mistyped glob is visible here rather than mid-run.

### Read-only by default

`writable` is the one constraint that **widens** rather than narrows, so it is a
bool that defaults to the safe reading: a grant that says nothing delivers a
read-only bind. `Constraints.ValidateFor` refuses it outright on every other
kind — "writable applies to local_repo grants, not `github_pat`".

Read-only is the useful default rather than the merely cautious one. The common
case is a sandbox that needs to *read* a developer's checkout — build against it,
grep it, copy from it — and a read-only bind means a runaway harness cannot
rewrite the history of a repository that exists nowhere else. A project that
genuinely needs to commit asks for it.

A read-write grant is `--writable` on the CLI, `"writable": true` on the API, or
a checkbox on the dashboard's grant form — offered only for `local_repo` rather
than shown and ignored:

```console
$ cloop secret grant local-src --to project:/srv/app --repos api-service \
    --writable --ttl 8h
```

The same thing over HTTP:

```console
$ curl -X POST https://cloop.example.com/api/grants \
    -H "Authorization: Bearer $CLOOP_TOKEN" \
    -d '{"secret_ref":"local-src","subject":"project:/srv/app",
         "repos":["api-service"],"writable":true,"ttl_minutes":480}'
```

A read-write grant carries `writable` in its constraint summary, in
`cloop secret grants` and in every audit row; a read-only one carries nothing at
all there, because the absence *is* the default.

### Not every executor can receive it

**This grant is the one an executor can refuse outright, and the refusal is the
part to read before you rely on it.** (The other refusal is `secret_files`,
which is about an executor that cannot receive a lease's *files* — see
[Secret file delivery](../architecture/executors.md#secret-file-delivery). This
one is narrower and harder: it is about an executor that cannot reach the hub's
filesystem at all, which no protocol version fixes.) The same grant reaches a
workload three different ways, and which one is correct is a property of the
driver:

| Executor | What happens | `SupportsHostMounts` |
| --- | --- | --- |
| `container` (including Kata) | each repository is bound at `/repos/<name>` | ✅ |
| `localprocess` | no mounts at all — it shares the hub's filesystem, so the repositories are already visible at their own paths, and the environment names *those* | ❌ (`SharesHostFilesystem` carries it instead) |
| `kubernetes`, `remote` | **refused** | ❌ |

Kubernetes and remote-agent executors run on a machine that has never seen these
files. There is no rendering of the grant that is not a lie, so the run does not
start:

```
executor: invalid spec: executor k8s-prod (kubernetes) cannot receive
repositories from the control-plane host, but this project holds a local_repo
grant for api-service, shared-proto. Bind the project to a container or Kata
executor running on the hub, or publish the repositories over https and grant a
github_pat instead
```

A hard error rather than a warning, because this is the exact point at which "I
granted my checkouts to this project" and "I bound this project to a remote
sandbox" turn out to be incompatible, and the person who needs to know is the one
who just pressed Run. The alternative is a harness that starts anyway and reports
that the repository is empty.

On `localprocess`, `writable: false` is **not enforced**. The harness runs as the
hub user against the repositories' real paths, so it can write to them whatever
the grant says; cloop logs a line saying so at start. That driver already has the
whole filesystem — it is the one an operator turns off first (`executors:
allow_host_process: false`) — so the grant is a routing decision there, not a
boundary. Bind a container executor to make read-only mean read-only.

`SupportsHostMounts` is **not** implied by `SharesHostFilesystem`, and the middle
row of that table is why: `localprocess` shares the filesystem and can bind
nothing. Only a driver that both runs on the hub *and* has a mount namespace to
bind into can honour the field. The same gap is named `host_mounts` when a spec
carrying host mounts is placed or failed over across a fleet — see
[Placement](../architecture/executors.md#placement).

### Revocation releases it at the end of the run

Revoking a `local_repo` grant behaves differently from revoking a token, and the
difference is a genuine limitation rather than an oversight. A revoked lease's
files are wiped and its environment variables scrubbed, but a bind mount already
in a running sandbox's mount namespace cannot be taken back from outside it. The
grant stops being *re-issued* immediately — the next lease renewal, at most 15
minutes away, will not contain it, so no new run gets the repository — but the
run already holding it keeps it until it exits.

To cut access to a repository *now*, stop the workload: the dashboard's Stop
button, or [cordon the executor](../architecture/executors.md#placement). There
is no top-level `cloop stop` command.

### Containment

The operator names a root; nothing under it may redirect the bind out of it.
That is the whole security argument for this kind, and it rests on one rule:
**every candidate path is resolved with `EvalSymlinks` and re-checked against the
resolved root.** A symlink planted at `<root>/evil -> /` resolves to `/`, which is
not under the root, and is dropped — regardless of who created the link.
Containment is tested with `filepath.Rel` rather than a string prefix, so a root
of `/home/dev/src` does not accidentally admit `/home/dev/src-other`.

Resolution happens once, when the lease is issued, and the resolved path is what
the driver binds — the container driver deliberately does *not* re-resolve, since
it no longer knows the root to check against. The window that leaves is between
issuing the lease and starting the sandbox: someone able to write to the granted
root itself could swap a component in that interval. A sandbox holding a
read-only grant cannot do this (it can write inside a repository, not to the
directory that holds it), so the exposure is to something already running as the
developer on the hub — but a root that untrusted processes can write to is not a
root worth granting.

Resolving *first* is also what makes a symlinked checkout work, which is how
plenty of people arrange a source tree: the link is followed, and then the result
is required to be inside the root. A root that is itself a symlink is fine for
the same reason — it is resolved before anything is compared against it.

Names are checked separately from paths. A repository directory whose name
contains a colon would append mount options, or a third path, to the container
runtime's `-v` flag; one that is `.` or `..`, or that contains a slash, a
backslash, a NUL or a newline, would not be a direct child at all; and one over
128 characters is refused outright. An entry under the root that fails this is
skipped rather than failing the lease, because it is a property of what happens
to be sitting in the directory and not of the grant — otherwise anyone who can
write to the root could break an unrelated project's runs by creating a file
there. The check runs again immediately before a driver receives the mount,
since the two moments can be separated by a store round trip and this is the one
material kind that carries a host path verbatim into a runtime flag.

Revocation has one extra obligation here. Scrubbing a credential file is
something the hub can do; taking a bind back is not — the hub cannot reach into a
running sandbox's mount namespace — so the driver has to unbind, and the mounts
are recorded on the lease for exactly that reason.

---

## Host devices

`local_repo` hands a workload paths. This one hands it **hardware**: device nodes
on the executor's host, opened to one project. It is for the bench with
instruments on serial lines, the box with a GPU in it, the task that needs
`/dev/net/tun` to build an interface of its own.

It is a grant for the reason `local_repo` is, one notch sharper. A device node is
an authority over the machine — `/dev/ttyUSB0` is a serial line into whatever is
plugged in, `/dev/nvidia0` is a compute unit with its own memory and its own
history of escapes — and the file that would otherwise carry it,
[`.cloop/sandbox.yaml`](../reference/sandbox.md), is repo-committed. A `devices:`
key there that could name `/dev/anything` would turn "merge this pull request"
into "hand over the hardware", which is why that file has no path-shaped key at
all. So the operator owns the inventory and the project owns the *selection*:
`capabilities.devices` picks by **name** from what the project already holds, and
picking fewer is the only freedom it has.

The payload is the host's inventory, stored once:

```
# rack 3, bench A
serial0=/dev/ttyUSB0
serial1=/dev/ttyUSB1
# a logic analyser, read-only: nothing should be able to reprogram it
analyser=/dev/ttyACM0:r
# remapped, so a project's code does not change when the hardware moves
accel=/dev/nvidia0:/dev/accel0:rw
accelctl=/dev/nvidiactl:rw
```

```console
$ cloop secret mint bench-hw --kind host_device --file ./bench-hw.txt
✓ minted bench-hw (host_device) as sec_03c245577f4b645d30e23a1c
  no grant yet — nothing can use it until you run 'cloop secret grant'
```

One entry per line, `name=/dev/source[:/dev/target][:mode]`. The mode is `r`, `rw`
or `rwm`, and an omitted one means **`rw`** — what a device is actually useful
with, and still short of `mknod`. A second path in the middle field remaps the
node, which is what makes a grant portable: a project told it has `accel` does not
need to know that *this* host enumerates the card as `nvidia0`. Blank lines are
skipped and a line beginning `#` is a comment, so the inventory keeps its
annotations and can live in configuration management. At most **256 lines** are
read — a host's grantable hardware is a short list, and parsing an unbounded one
on a path an operator's browser can reach is a memory-exhaustion primitive rather
than a feature.

The name is the handle everything downstream refers to — the grant's allowlist,
the sandbox spec, the audit row — so it is held to the same shape as a repository
name: at most 64 characters, and no colon, slash, backslash, equals sign, space,
NUL or newline. Two entries may not share a name, and two may not share a
sandbox-side target; either collision would otherwise be resolved by argv order,
and a workload could not tell which piece of hardware it had opened.

**Existence is deliberately not checked when the inventory is stored.** The secret
is minted on the hub and may be honoured by a container executor on another
machine, so "this path exists" is not a question the broker can answer about the
right host. What is checked is the shape, which is host-independent — see
[What the inventory refuses](#what-the-inventory-refuses).

Each grant then opens a different slice to a different project:

```console
$ cloop secret grant bench-hw \
    --to project:/srv/projects/firmware \
    --devices serial0,analyser \
    --writable \
    --ttl 8h
✓ granted bench-hw to project:/srv/projects/firmware
  grant:       grant_662a06d49509af57fdad8186
  constraints: devices=analyser|serial0 writable
  expires:     2026-09-14T01:12:54Z (in 8h0m0s)
```

**`--devices` is required, and it matches names rather than paths.** `serial0` is
exact, `gpu*` is a glob, and `*` alone allows every device in the inventory.
Matching is **case-sensitive**: these handles are chosen by an operator and
matched exactly, and folding would make a grant on `gpu0` also open `GPU0` —
which, if both existed, would be two different pieces of hardware nobody named.
At most 16 devices may be opened by one grant, the same ceiling a sandbox spec can
carry, so a grant cannot mint more than the dispatch path will accept.

Omitting it is refused at creation, not at delivery:

```console
$ cloop secret grant bench-hw --to project:/srv/projects/firmware --ttl 8h
Error: secretbroker: invalid constraint: a host_device grant needs a device
allowlist (--devices serial0, or --devices '*' for every device in the inventory)
```

So is an allowlist that matches nothing. The grant asserts that this hardware is
reachable, and delivering an empty device list would start a harness that
discovers the problem as an `ENOENT` on a path it was told to expect.

### What the sandbox actually gets

Each granted device appears at its **target** path — the same path as on the host
unless the inventory remapped it — with the access mode the grant resolved to:

```
devices: /dev/ttyACM0  ->  /dev/ttyACM0   r
         /dev/ttyUSB0  ->  /dev/ttyUSB0   rw
env:     CLOOP_HOST_DEVICES=analyser,serial0
```

`CLOOP_HOST_DEVICES` lists the **names**, and never the host paths. The path is a
fact about one machine's hardware layout; the name is what the project was granted
and what its code refers to, and a workload that needs a path opens the device it
was given. Putting host paths in the environment would publish the host's hardware
layout to every process in the sandbox for no benefit.

Dry-run it like any other lease:

```console
$ cloop secret lease --project /srv/projects/firmware --executor bench-01
1 material(s), lease expires 2026-09-13T17:27:54Z

  bench-hw (host_device)
    grant:       grant_662a06d49509af57fdad8186
    constraints: devices=analyser|serial0 writable
    delivers:    host devices: analyser,serial0
    env:         CLOOP_HOST_DEVICES
```

The delivered list is sorted by name, because it reaches an audit row and a `Spec`
that `pkg/executorstore` persists, and neither should vary between identical runs.

A project selects from this by name in its own repository —
`capabilities.devices: [serial0]`, or the key omitted to take everything the
project holds. Naming a device the project has no grant for is an **error**,
unlike `env:`, where an unheld name simply forwards nothing: a missing variable
degrades a run, whereas a missing device node makes a firmware build meaningless.
See the [sandbox spec reference](../reference/sandbox.md).

### Narrowing is the only direction

`writable` widens, so — as for `local_repo` — it is a bool that defaults to the
safe reading, and the invariant is the *direction* rather than the value. A
constraint may take access away and may never add it:

- a grant **without** `--writable` narrows every device it opens to `r`,
  whatever the inventory recorded;
- a grant **with** `--writable` cannot promote an entry the inventory recorded as
  `:r`. The analyser above stays read-only under the `--writable` grant that
  opened it.

That asymmetry is what lets one inventory serve several projects. An operator who
decides "nothing may ever reprogram the analyser" writes `:r` once, at the
inventory, and no grant, spec or flag downstream can undo it.

### The access mode is not a boundary on every host

**Read this before relying on a read-only device grant.**

The mode becomes the third field of the runtime's `--device src:dst:perms`, which
programs the container's *device cgroup*. On cgroup v1 that is the devices
controller; on cgroup v2 it is an eBPF program attached to the container's cgroup,
and whether it is attached at all depends on the kernel, the runtime build and the
cgroup delegation — none of which cloop can interrogate. On a host where it is not
attached, **a device granted `r` is readable and writable**, because the node
inside the sandbox carries the host node's file mode and `/dev/zero` is `0666`
nearly everywhere.

So the mode is defence in depth and not a boundary cloop can promise. The
container driver's preflight — phase one of `cloop executor test` — says so rather
than leaving the stronger reading to be assumed:

```
warn devices     a host_device grant's access mode (r/rw/rwm) is programmed into the
                 container's device cgroup, whose enforcement depends on this host's
                 cgroup version and runtime build and cannot be verified from here —
                 on a host where it is not attached, a device granted "r" is writable
                 because the node keeps its host file mode
                 fix: where read-only access must be enforced, set it on the host node
                 itself (chown root:cloop-ro /dev/… && chmod 0640) so the sandbox UID
                 cannot open it for writing regardless of cgroups; verify with
                 `cloop executor test`
```

The warning is unconditional, and deliberately so: it is a statement, not a probe.
Establishing whether the cgroup rule is enforced would mean starting a container,
granting it a device read-only and trying to write — a container run and an image
dependency inside a command an operator may be running on a node with nothing
pulled yet.

**The control that holds on every host is the node's own ownership and mode.** The
sandbox runs as the project directory's owner UID, so a device at `crw-rw----
root:dialout` is unopenable by a sandbox whose UID is not in that group, whatever
the cgroup does. An operator who needs read-only access *enforced* sets it there —
`chown`/`chmod`, with a udev rule so it survives a re-plug. The full recipe is in
[critical hosts as cloop executors](enterprise-hosts.md#what-the-access-mode-does-and-does-not-enforce).

cloop still emits the mode, because on the hosts where the cgroup rule *is*
enforced it is enforced exactly, and withholding `mknod` by default costs nothing.

### Not every executor can receive it

`local_repo` reaches a workload three ways depending on the driver; this one
reaches it on **one**, and the other three are refusals rather than renderings:

| Executor | What happens | `SupportsDevices` |
| --- | --- | --- |
| `container` (including Kata and gVisor) | each device is exposed at its target path with the granted mode | ✅ |
| `kubernetes` | **refused** — Kubernetes does not take device paths | ❌ |
| `remote` | **refused** — the grant names a path on the *hub's* host, and the agent has no sandbox to put a device into | ❌ |
| `localprocess` | not exposed and **not enforced**; a warning is logged | ❌ |

On `kubernetes` a device plugin owns the node and hands a container whichever unit
it has free, in response to an extended resource request — so there is nothing
honest to do with a path-shaped grant, and mounting `/dev/nvidia0` as a hostPath
from whatever node the scheduler picked would expose an unrelated piece of *that*
node's hardware, which is the one outcome worse than refusing. (`HostDevice`
carries a `kubernetes_resource` field for the resource-request shape this driver
would need; it is not consumed yet.)

On `remote` two things stand in the way and only one of them is a missing feature.
A grant naming `/dev/ttyUSB0` on the hub says nothing about `/dev/ttyUSB0` on a
machine in another building; and the agent runs each workload with `localprocess`
— a plain process in its own namespaces — so it has no sandbox to put a device
*into*. Pass hardware into a confined sandbox by running the container executor on
the machine that has the hardware.

`localprocess` is the one warning rather than error, because the workload is a
plain process in the hub's own namespaces: every device node the hub user can open
is already open to it. There is nothing to expose and nothing that could have been
withheld, so the grant is satisfied in the weakest possible sense. It must not be
silent — a dashboard showing a scoped device grant on a workload that has the whole
of `/dev` would be describing a boundary that does not exist — so a line goes to
the hub's stderr naming the grant and telling you to bind a container executor to
make it one.

The refusals land at placement, naming both facts:

```
executor: invalid spec: executor k8s-prod (kubernetes) cannot expose host devices
inside a sandbox, but this project holds a host_device grant for serial0. A device
grant names hardware on one machine, so bind the project to a container or Kata
executor running on the host that has it
```

A hard error rather than a warning, for the same reason `local_repo`'s is: this is
the exact point at which "I granted this bench's hardware to that project" and "I
bound that project to a cluster" turn out to be incompatible, and the person who
needs to know is the one who just pressed Run. The same gap is named `devices`
when a spec carrying devices is placed or failed over across a fleet — see
[Placement](../architecture/executors.md#placement).

### Revocation lapses when the workload exits

This is the same limitation `local_repo` has, and harder. A device already in a
running sandbox's cgroup and mount namespace cannot be taken back from outside it,
exactly as a bind mount cannot. Revoking the grant stops it being *re-issued*
immediately — the next lease, at most 15 minutes away, will not contain it, so no
new run gets the hardware — but the run already holding it keeps it until it exits.
The devices are recorded on the lease for the audit trail rather than for
revocation, which is the honest reading of what the hub can and cannot do.

Narrowing that window means revoking and then stopping the workload — from the
dashboard's Stop button, or by
[cordoning the executor](../architecture/executors.md#placement). There is no
top-level `cloop stop`:

```console
$ cloop secret revoke <grant-id>
✓ revoked grant_7f3a1c
  already-materialised credentials survive until the workload exits
```

**Grant TTLs are the routine control here, not revocation.** Eight hours for a
bench session is better than a week, because the grant lapsing is what makes it a
session rather than a standing entitlement to the machine's hardware.

### What the inventory refuses

The broker cannot know which host will honour a device path, so it checks the
things that are true of any host. A path must be absolute, canonical (`/dev/../etc`
is refused rather than cleaned, because the two differ exactly when someone wrote
something they did not mean), at most 256 characters, and free of backslashes, NULs
and newlines.

Beyond that, two classes are refused outright.

**Devices whose exposure would waive the sandbox entirely.** `/dev/mem`,
`/dev/kmem`, `/dev/kcore`, `/dev/port`, `/dev/msr` and `/dev/cpu` exist to give
unmediated access to the machine, and whole host disks — `/dev/sda`,
`/dev/nvme0n1`, `/dev/vda` — hand over every filesystem on it:

```
secretbroker: malformed secret payload: host_device line 1: device "ram" source
path "/dev/mem" maps all of physical memory, including kernel text, so granting it
would waive every isolation guarantee the sandbox provides
```

This is a denylist on top of an allowlist, which is normally a smell. It is here
because the allowlist above it is "an absolute path under `/dev` that an operator
typed", and an operator typing `/dev/mem` has made a mistake no downstream layer
can catch: every confinement cloop advertises would be decoration. Grant a
partition, or a directory as a `local_repo`, instead.

**Anything outside `/dev`.** The field's contract is a device node, and a regular
file arriving here would be a host bind mount wearing a device's name — bypassing
the `local_repo` grant that exists for exactly that, and the symlink containment
that comes with it:

```
secretbroker: malformed secret payload: host_device line 1: device "src" source
path "/srv/git" is not under /dev; grant a host file or directory as a local_repo
instead
```

Both checks exist twice on purpose, at the two ends of the same pipe. The broker's
copy is the one that has to be *helpful* — over the API and the dashboard the
inventory is parsed as it is stored, so the error appears in the dialog in front
of the person who typed the path. `pkg/executor`'s copy is the one that has to
*hold*, and it runs again immediately before a driver renders a runtime flag,
because a `Spec` reaches that point having been persisted and re-hydrated and this
is a field that carries a host path verbatim into the argv of a root-privileged
runtime CLI.

The end-to-end host setup — the inventory, the udev rules, gVisor, the egress
filter and how they compose on one bench machine — is
[critical hosts as cloop executors](enterprise-hosts.md).

---

## Host network interfaces

`host_device` cannot carry a network interface. A netdev is not a node under
`/dev`, so there is nothing to bind and no cgroup rule to write, and neither
runtime has a flag for it. `host_interface` is the kind that can: it **moves**
an interface out of the executor's network namespace and into the sandbox's,
giving the workload a seat on the segment rather than a route through the host.
That is what makes ARP, DHCP and raw Ethernet work, which is the point of
plugging a machine into a board in the first place.

It is the widest grant this broker issues, and the only one that takes something
*away* from the executor: an interface lives in exactly one namespace, so the
host cannot use it while the run holds it.

```bash
$ cloop secret mint bench-net --kind host_interface --file - <<'EOF'
# rack 3, bench A — a veth end that lands on the bench bridge
dut=bench-sbx,target=eth1,address=172.31.99.200/24
# a physical port wired straight to the board
can0=enp3s0,target=eth1
# a capture port: no address, jumbo frames, raw L2 only
capture=enp4s0f1,mtu=9000
EOF
✓ minted bench-net (host_interface) as sec_5f19c0a3b8e27d41

$ cloop secret grant bench-net \
    --to project:/srv/projects/firmware \
    --interfaces dut \
    --ttl 8h
```

The line format is `name=ifname` plus optional comma-separated attributes —
`target=`, `address=` (a CIDR), `gateway=` (needs `address=`) and `mtu=`.
Comma-separated rather than colon-separated because `fd00::10/64` is full of
colons. `--interfaces` is required for the reason `--devices` is: a grant with
no allowlist would open every segment in the inventory.

`.cloop/sandbox.yaml` then selects from what the project holds, and can only
shorten the list:

```yaml
capabilities:
  network: bench-egress
  interfaces: [dut]
```

Three refusals are worth knowing before you mint one:

| Refused | Why |
| --- | --- |
| `lo`, `docker0`, `podman0`, `cni-podman0`, `virbr0`, `br-*` | moving one disconnects the host or every container on it. A Docker per-network bridge is what the sandbox's veth peer *attaches to*, not what gets moved |
| the interface carrying the host's default route | checked on the executor at attach time, where the routing table can be read. On a remote bench this is the difference between a lab machine and an unreachable one |
| a Kata or gVisor executor | the move succeeds and the workload still sees nothing, because both build their view of the network when the sandbox starts. Refused at placement rather than attempted |

Revocation has the same honest limit as `host_device`: an interface already
inside a running sandbox's network namespace cannot be reached from outside it,
so a revoked grant lapses when the workload exits. Stopping the run is what cuts
it immediately — and stopping gracefully is also what returns a veth pair to the
host intact, since the kernel deletes virtual interfaces along with the
namespace rather than handing them back.

The full bench recipe — the bridge, the veth pair, the runtime constraints and
the start-up window — is
[Network interfaces: L2 passthrough](enterprise-hosts.md#network-interfaces-l2-passthrough).

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
downgraded after a placement. Fix it by upgrading the device: copy the new
`cloop` binary onto it and run

```bash
sudo cloop executor agent install --upgrade
```

which replaces the binary and restarts the service, leaving the unit file and
the enrollment credential untouched. It is idempotent, so it is safe to re-run.
See [Executors](../architecture/executors.md) for the build-version reporting
that tells you which devices need it.

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
