# Granting secrets and egress

How to give a sandbox the GitHub, cluster or Internet access it needs, and no
more, for as long as it needs it.

Every command and output block below comes from running the real binary, so
you can copy them.

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

The broker works with three things:

| | What it is | Lifetime |
| --- | --- | --- |
| **Secret** | the credential itself, sealed with AES-256-GCM under its own per-row data key. It leaves the broker in plaintext only inside a Material | until deleted |
| **Grant** | who may use it, narrowed by kind-specific constraints, until when | `--ttl`, default 24 h |
| **Lease** | a short-lived, *minimised* copy of every grant that matches one (executor, project) pair | ≤ 15 min |

Executors receive leases, never the store. Every lease and every renewal is
computed from the current grants, so a revoked grant is never issued again.
Revoking a grant also takes it back at once from the workloads that already
hold it, without waiting for their lease to end (see
[Revoking a grant](#revoking-a-grant)).

**How each kind is narrowed.** For `kubeconfig`, `registry` and `env`, the
broker rewrites the payload before delivery, and whoever holds the narrower
credential can't widen it. `github_app` is narrowed by GitHub: the hub keeps the
App's private key and, for each lease, mints a fresh installation token (valid
for about an hour) scoped to the grant's repositories and permissions.
`github_pat` is the one GitHub kind enforced where it is used instead, because
GitHub has no API to narrow a token that was already issued. That is why
[`github_app` is the one to prefer](../security/model.md#github_pat-versus-github_app).
`egress_proxy`'s allowlist is enforced by the executor's network policy.
`local_repo` is narrowed by selection: only the repositories its allowlist
matches are bound, read-only unless the grant says otherwise.
[The security model](../security/model.md#what-is-not-mitigated) says which kind
gets which kind of protection.

Everything fails closed. A constraint that can't be parsed or satisfied, an
expired or revoked grant, or a payload that minimises to nothing produces a
denial and an audit row, never a wider credential.

---

## Minting a secret

```
cloop secret mint <name> --kind <kind> [--file <path> | --value <literal>]
```

| Kind | Payload |
| --- | --- |
| `github_pat` | a GitHub personal access token: a `github.com` token unless minted with `--github-host` for a [GitHub Enterprise Server](#github-enterprise-server) |
| `github_app` | GitHub App installation JSON: `app_id`, `installation_id`, `private_key`, optional `base_url`. The hub mints short-lived installation tokens from it and never delivers the key. The dashboard [finds the installation ID for you](#connecting-a-github-app-from-the-dashboard). [Worked example](#github-repositories-and-pats) |
| `kubeconfig` | a kubeconfig YAML document |
| `registry` | docker `config.json`, or `user:password` |
| `env` | one or more environment variables |
| `egress_proxy` | an outbound proxy endpoint, credentials optional |
| `local_repo` | an absolute path **on the hub host** to a directory of git repositories (or to a single repository) |
| `host_device` | an inventory of device nodes on the executor's host, one `name=/dev/path` per line |
| `host_interface` | an inventory of network interfaces on the executor's host, one `name=ifname` per line. Using one **moves** the interface into the sandbox, so the executor loses it for the life of the run. [Worked example](#host-network-interfaces) |

Pass the credential on stdin or with `--file`. `--value` puts it in your shell
history and the host's process table, as the flag's help text warns:

```console
$ echo 'ghp_examplesecrettoken' | cloop secret mint deploy-pat --kind github_pat
✓ minted deploy-pat (github_pat) as sec_56315798b775a67cad36ad43
  no grant yet — nothing can use it until you run 'cloop secret grant'
```

Nothing can use a minted secret until it is granted.

> Already using the flat `.cloop/secrets.enc` store? `cloop secret migrate`
> imports those entries into the broker. The legacy `cloop secret set/get/list`
> commands still work during the transition, but they give every secret to
> every workload, which is what the broker is there to prevent.

---

## Granting it

```
cloop secret grant <secret> --to <subject> [constraints] [--ttl 24h]
```

**Subjects** (who the grant applies to):

| Form | Matches |
| --- | --- |
| `project:/srv/app` | that project path exactly (canonicalised; `/srv/app-staging` does not match) |
| `executor:edge-01` | that executor id exactly |
| `label:region=eu,gpu=true` | executors the hub records with all of those labels; see [Label subjects](#label-subjects) |
| `any` | every requester (legacy imports only) |

**Constraint flags**, by kind:

| Flag | Applies to | Meaning |
| --- | --- | --- |
| `--repos` | `github_pat`, `github_app` | owner/repo globs, **required** (`--repos '*'` to opt out explicitly) |
| `--repos` | `local_repo` | repository *directory-name* globs under the granted root, **required** |
| `--permissions` | `github_pat`, `github_app` | e.g. `contents:read,pull_requests:write` |
| `--contexts` | `kubeconfig` | context allowlist |
| `--namespaces` | `kubeconfig` | namespace allowlist; at least one of contexts/namespaces is required |
| `--verbs` | `kubeconfig` | RBAC verb allowlist; omit for read-only (`get,list,watch`). Needs the [access monitor](../architecture/kubernetes-access.md) to be enforced |
| `--registries` | `registry` | registry allowlist, required |
| `--env-keys` | `env` | key allowlist; omit to deliver every key in the secret |
| `--hosts` | `egress_proxy` | host allowlist, required |
| `--devices` | `host_device` | device-*name* globs from the inventory, **required** |
| `--interfaces` | `host_interface` | interface-*name* globs from the inventory, **required** |

`--scope` is a grouping label for operators and grants nothing.

### Label subjects

A grant to `label:region=eu,gpu=true` reaches every executor that carries both
labels, on every path a credential takes: a run's lease, its egress proxy
session, the workspace fetch, and the Kubernetes driver's own cluster
credential. An executor's labels come from the hub's own records, never from
what the executor says about itself:

| Executor | Its labels |
| --- | --- |
| An enrolled device | The labels on its agent credential, chosen when the enrollment token was minted (`cloop executor enroll --label region=eu`, or the Enroll dialog) and changed later with the **Labels** button on its card (`PUT /api/executors/{id}/labels`, audited as `executor.labels`) |
| A virtual executor | Its device's labels. Its own registry row carries only the hub's bookkeeping label `parent=<device>`, which selectors don't match |
| A configured container or Kubernetes executor | `executors.container.labels` or `executors.kubernetes.labels` in the hub's configuration, read when the hub starts |
| The host-process executor, or one the hub has no record of | None, so no label grant reaches it |

The labels a device's agent advertises when it connects (what
`cloop executor agent --label` sets on the device) never count. Whoever controls
the device chooses those, so a device could claim `region=eu`.

When an executor's labels change, everything that came from a label grant is
checked again. Saving a device's labels immediately re-checks every running
lease and egress session on the device and its virtual executors. A credential
from a label grant that the new labels no longer match is taken back, from the
hub's copy and from every holder, as revoking the grant would (see
[Revoking a grant](#revoking-a-grant)). The lease keeps its other grants. Every
hub member re-checks the leases it holds once a minute, which is how an edit
made on another member reaches them. A hub restarted with different configured
labels takes back whatever they no longer match from the runs it adopts. Leases
and egress sessions record the labels they were checked against, so the process
that adopts a run checks it the same way.

Under each label grant, the Secrets panel lists the executors its selector
reaches now, or says that it reaches none, which usually means a typo in the
selector. The grant dialog shows the same while you type the subject.
`cloop secret grant` prints it after a label grant, and
`cloop secret lease --executor edge-01` shows the labels the hub records for the
executor it is dry-running.

A label selector describes machines, so a grant to one also reaches executors
that get the labels later (a device enrolled with them, or relabelled), as well
as those that have them now. Labels that no selector could name are refused when
you type them: a key with a space, `,` or `=`, or a value with `,`.

One more constraint applies only to `local_repo` and `host_device`:
`--writable`, the only constraint that widens access instead of narrowing it.
See [Read-only by default](#read-only-by-default) and
[Narrowing is the only direction](#narrowing-is-the-only-direction).

---

## Connecting a GitHub App from the dashboard

The CLI needs an `installation_id`, which GitHub doesn't show you directly. The
App's settings page gives you an App ID and a private key. The installation is
created later, by whoever installs the App on their organisation, and its ID
appears only in the URL of a settings page you may never open.

So the dashboard asks GitHub for it. Under **Settings → GitHub Apps**, paste the
App ID and the PEM and press **Find installations**. The hub signs a short-lived
app JWT, calls `GET /app/installations`, and lists every account the App is
installed on, with its type and whether it covers all repositories or a chosen
subset. Pick one, and the `github_app` secret is stored with that ID filled in.
Nothing is saved until you pick; the key is only held while the dialog is open.

Then, on a project's **Overview** tab, **Repository Access** lists what the
project may reach and offers the rest. Choose an App and press **List
repositories** to list the installation's repositories, so the names you tick
are ones GitHub has confirmed the App can see. Pick **Read only** or **Read and
write** (`contents:read`, or `contents:write` plus `pull_requests:write`, and
nothing else), and the grant is created for `project:<path>`.

**Read and write** also shows **Push to branches**. Leave it empty to let the
project push wherever the hub allows, or list the branches it may push to
(`cloop/*`, `feature/**`) to keep it off everything else, including the default
branch. The line under the field tells you, before you save, whether this hub
can enforce the list; see
[Limiting pushes to particular branches](#limiting-pushes-to-particular-branches).
Each assignment's row shows its branches and what they mean on this hub, and
**Edit** changes the access level or branches of an existing assignment in
place.

This is the same broker call `cloop secret grant` makes, so a grant created
either way shows up in both places and is recorded the same way in
`cloop hub audit list`.

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

**Pattern rules.** `myorg/*` matches every repository directly in the org and
doesn't cross a `/`, so `myorg/team/tool` is refused. `myorg/tool` is an exact
name, not a prefix, so `myorg/toolkit` is refused. `*` and `*/*` mean
everything. Matching is case-insensitive, as GitHub names are. (`local_repo` is
the exception: its patterns match directory names, which are case-sensitive on
Linux, so `api` doesn't open `API`.)

### What the sandbox actually gets

```
files:  github-token            0600   the raw token
        git-credential-cloop    0700   a POSIX shell credential helper
        gitconfig               0600   installs the helper, sets credential.useHttpPath
env:    GIT_CONFIG_GLOBAL=<lease dir>/gitconfig
        CLOOP_GITHUB_REPO_ALLOWLIST=myorg/*
        CLOOP_GITHUB_PERMISSIONS=contents:read
```

`GITHUB_TOKEN` and `GH_TOKEN` are not set. Every tool in the sandbox would read a
token there and could reach every repository the PAT can, so the token is only
exported that way when the allowlist is `--repos '*'`. For any narrower grant,
the credential helper is the only way the token is delivered.

The helper enforces the allowlist, so it is strict: it answers only `get`, only
for `https`, only for the host `github.com` exactly (a lookalike such as
`github.com.evil.test` gets nothing), only for a single-slash `owner/repo` path,
and only when that path matches the allowlist. A request without a path, which
is what git sends when `credential.useHttpPath` is off, gets no answer.
`pkg/secretbroker/githubpat_test.go` runs all of this against `/bin/sh` instead
of inspecting the script as text.

So `git clone`, `git push` and `gh` work normally inside `myorg/*`, and the same
commands against `otherorg/private` fail to authenticate.

**Several GitHub grants on one project** (say, read access to a library and write
access to the project's own repository) are delivered together. Each grant after
the first gets its own `github-token-2`, `git-credential-cloop-2` and so on
(`git-proxy-credential-2` behind the proxy), and the single `gitconfig` installs
every helper in turn. Git asks each helper and takes the first answer. Each
helper answers only for its own grant's repositories, so every repository is
authenticated by the grant that names it. A grant whose allowlist is a wildcard
is asked after the ones that name repositories outright.
`CLOOP_GITHUB_REPO_ALLOWLIST` lists every grant's repositories, but a permission
list, a proxy mode or a branch rule is only announced when every grant agrees on
it. Older builds wrote both grants' files to the same paths, so a project
holding two couldn't run on any executor that receives files
(`secret_files[N] repeats path …/github-token`).

### The helper's limit, and what removes it

The helper protects less than it seems to. It runs inside the sandbox and reads
`github-token`, which is also inside the sandbox. A workload that ignores git
and reads the file has the whole token. So for a `github_pat`, the allowlist is
enforced against git, not against the workload: it stops an innocent
`git clone otherorg/private`, but not a deliberate attempt.

This matters most in the usual case. A personal access token normally carries
`repo` for everything its owner can see, so a user who grants one to a project
gives the project all of that, unless something else limits it.

**The [git interception proxy](../git-interception-proxy.md) closes this gap.**
With `executors.git_proxy.enabled: true`, a `github_pat` is delivered
differently: the hub keeps the token, and the sandbox gets a proxy session
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
        CLOOP_GIT_PUSH_REFS=refs/heads/cloop/**     # read-write sessions only
        CLOOP_GITHUB_PUSH_BRANCHES=cloop/*           # when the grant lists branches
```

There is no `github-token`. The allowlist is enforced on the network path, which
the workload can't avoid, instead of by a script it can bypass. That changes two
things:

- **The allowlist is enforced.** The proxy checks `myorg/*` outside the sandbox
  on every request. A request for `otherorg/private` gets a 403 from the proxy
  and an audit row, whatever the workload does with its files.
- **`--permissions` takes effect.** A grant that authorises no write
  (`contents:read`, or no `--permissions` at all) gives a session that can't
  push, even though the PAT behind it can. Deletes are never granted. The hub's
  configured `allowed_refs` is the upper limit, and a grant can only narrow
  within it.

`git clone`, `git push` and submodules work as before, because the rewriting is
transparent: a remote of `https://github.com/myorg/tool` or
`git@github.com:myorg/tool` goes to the proxy without the workload doing
anything. What stops working is `gh` and anything else that talks to the GitHub
API, which isn't git traffic and has no proxy to go through. Those need a
`github_app` grant, whose token GitHub has already narrowed.

If `executors.git_proxy.enabled` is true and the proxy isn't running, a
`github_pat` lease fails. It never falls back to writing the token into the
sandbox.

**These three files have to reach the sandbox**, and the executor decides how.
The hub writes them to its own disk only for the host-process driver. A
container gets a private per-run tmpfs, bind-mounted read-only. A Pod gets a
per-run Secret, projected read-only. An edge device is sent the bytes on the
start frame and writes them itself. An executor that can't receive files at all
(an agent below protocol v6) refuses the run with the `secret_files` placement
constraint, instead of starting a sandbox whose `GIT_CONFIG_GLOBAL` points at
nothing. See [Secret file delivery](../architecture/executors.md#secret-file-delivery).

**`github_app`** is granted with the same `--repos` / `--permissions` flags, but
the payload is a strict JSON document, not a token, and the sandbox doesn't
receive what you stored.

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

`app_id` and `installation_id` come from the App's settings page. `private_key`
is the PEM that the **Generate a private key** button downloads, with its
newlines escaped as `\n` (`jq -Rs` does this). Both IDs must be integers and the
key must parse as RSA. `cloop secret mint` and the dashboard refuse a malformed
payload, so it is never stored only to fail inside somebody's run. Add
`"base_url": "https://ghe.example.com/api/v3"` for GitHub Enterprise Server.

When a lease is issued, the hub signs a nine-minute JWT with that key and
exchanges it for an installation token narrowed to the repositories the grant
allows and the permissions it names. Only the token is delivered. The private
key never leaves the hub, each token expires in about an hour, and releasing or
revoking the lease calls `DELETE /installation/token`, so the token stops
working at GitHub and not only on the sandbox's disk. A run that needs GitHub
for more than an hour keeps access: the hub mints a new token before the old one
expires and swaps it in (see
[keeping the token past GitHub's hour](#keeping-the-token-past-githubs-hour)).
Each destruction is audited as `github_app.token_destroy`. It has its own action,
separate from `secret.revoke`, because it happens on every normal task teardown
and would otherwise bury the grants an operator actually withdrew. A DELETE that
GitHub refuses is recorded as a denial that says how long the token stays valid.
That is the row to search for during an incident.

Two things to know before you choose this kind:

- **The hub needs to reach `api.github.com`.** If minting fails, the grant is
  denied. The hub never falls back to delivering the key. An air-gapped hub has
  to use `github_pat`.
- **A grant naming a repository the App isn't installed on is refused**, and
  the error names the missing repository, instead of producing a token that gets
  a 404 on the first clone. `--repos 'acme/*'` is resolved against the
  installation's actual repository list, so the same check covers globs.

[The security model](../security/model.md#github_pat-versus-github_app) compares
the two kinds and says when a PAT is still the right choice.

With the [git interception proxy](../git-interception-proxy.md) on, the hub
holds an App token as it does a PAT: the sandbox gets a proxy session, and the
token never enters it.

### Keeping the token past GitHub's hour

An installation token works for an hour, but a run's lease is kept alive for as
long as the run. So the hub replaces the token when about ten minutes of its
hour are left:

- **The new token has the same scope as the first**: the same installation, the
  same permissions and the same repositories, by the IDs GitHub was first given.
  The grant's globs aren't resolved again, so a repository added to the
  installation since dispatch isn't picked up. GitHub's answer is held to the
  permissions it granted the first token, and a refresh that comes back wider is
  destroyed instead of delivered.
- **Only while the grant still allows it.** The grant is read again on every
  refresh. It must still be active and issued to the lease's holder, its secret
  must still exist and name the same installation, and the lease must not have
  been released.
- **The old token is destroyed** at GitHub once nothing uses it any more.

Who replaces the token depends on where it is:

| The grant is delivered | Who refreshes | How the workload gets the new token |
| --- | --- | --- |
| through the [git proxy](../git-interception-proxy.md) | the proxy session, on the first request in the last ten minutes (one at a time; other requests wait) | it doesn't need to: the session presents the new token upstream from then on, and destroys the old one when the last request using it finishes |
| as `github-token` on a hub-local host or container executor | the lease's keepalive, once a minute | the file is replaced in place by a rename inside the lease directory. The container has the whole directory bind-mounted, which makes the rename visible inside it |
| as `github-token` on an edge device | the keepalive, through the agent | a `secret_refresh` frame (protocol v17): the agent rewrites the file in the lease directory it created, which a container on the device also has bind-mounted whole |
| as `github-token` on Kubernetes | the keepalive | the run's lease Secret is patched, and the kubelet syncs the Pod's Secret volume within its sync period. The volume is mounted as a directory with no `subPath`, which is the form the kubelet keeps in sync |

git's credential helper reads `github-token` on every call, so the next git
operation uses the new token without the workload doing anything. Without the
proxy, the old token is destroyed two minutes after its replacement reached the
workload, because git reuses the credential it read for the rest of one
invocation, and a fetch that started shortly before the rewrite needs the old token
for a few more requests. On Kubernetes the old token is left to expire instead,
since the kubelet's sync has no completion signal the hub could wait for.

Each new token is recorded as an allowed `secret.renew` row naming the lease,
grant, secret and run, the scope it was minted at and the new expiry (and, with
the proxy, the session presenting it). Each delivery to an executor holding the
file is a `lease.refresh` row: allowed when every workload has the new file,
denied when it couldn't be delivered. The new token is also added to output
redaction on both sides of the sandbox boundary (the log stream, a terminal
already attached to the workload, and the project state a feature run hands
back), so it is scrubbed from a workload's output like the first.

**When a refresh is refused.** If the broker or GitHub refuses a refresh (the
grant was revoked or expired, the lease released, the installation suspended or
uninstalled, a repository removed from it, or the App's key deleted), the
grant's access ends as it would on revocation. Every token the lease holds for
it is destroyed at GitHub, a proxy session presenting it is closed (its next
request gets HTTP 401, and its `gitproxy.session_closed` row says *upstream
credential will not be renewed* and why), and a denied `secret.renew` row records
the refusal. For a run without the proxy, the project journal says which grant's
access ended and why. A failure that may be temporary (GitHub unreachable,
rate-limiting or answering 5xx) is also a denied `secret.renew` row, and is
retried every minute while the current token still works.

**When it can't be delivered**, nothing is minted. A device whose agent speaks a
protocol older than v17 can't take the frame. The run is dispatched as before
and keeps the token it was given, the project's journal says once that its
GitHub access ends when that token expires (naming the agent's protocol and the
upgrade), and a denied `lease.refresh` row records it. On a Kubernetes executor
whose Role lacks the `patch` verb on `secrets`, the patch fails, and the denied
row says which rule to add.

A refresh can't reach environment variables. A `"*"` allowlist also exports the
token as `GITHUB_TOKEN` and `GH_TOKEN`, and an environment variable in a running
process can't be changed. Those keep the first token, which is therefore left to
expire at its hour instead of being destroyed early. For the same reason
`CLOOP_GITHUB_TOKEN_EXPIRES_AT` still shows the first token's expiry. git, which
reads the file, isn't affected.

The refresh survives a restart of the hub process that minted the token, because
the run's lease does: the process that adopts the run takes the lease over, keeps
it alive and releases it (see
[a hub restarted mid-run](../architecture/executors.md#the-project-comes-back-task-20339)).
The token's slot comes with it. Next to the lease, `app_token_slots` records the
scope the first token was minted at (installation, repository IDs, the
permissions asked for and the ones GitHub granted), the file it was delivered
in, and when the workload's token expires, but never the token itself. The new
holder's keepalive renews the file before that expiry as the first process
would have, minting a new token at the recorded scope and delivering it over the
same v17 `secret_refresh` frame. The old token, which only the stopped process
knew, lapses at its hour.

A recorded scope wider than the grant now allows (an edited record, or a
narrowed grant) is not renewed: a denied `secret.renew` row says why, and the
file keeps its token until its hour. Before minting its first token at a
recorded scope, the new holder reads the installation's repositories once and
keeps only the recorded ones the grant's allowlist still admits. The allowed
`secret.renew` row notes any it dropped, and a record left with none is refused.
If the slots can't be read when the lease is taken over (the database is busy),
nothing is refused: the keepalive reads them again before a token is due. With
the git proxy, the session presenting the token is restored the same way and
mints its own token at once; see
[a hub restarted mid-run](../architecture/git-proxy.md#a-hub-restarted-mid-run).

### Limiting pushes to particular branches

A grant that authorises a push can say where pushes may go:

```console
$ cloop secret grant deploy-app --to project:/srv/app \
    --repos acme/tool --permissions contents:write \
    --branches 'cloop/*,feature/**'
✓ granted deploy-app to project:/srv/app
  grant:       grant_558134c7fcbb6d2823b00574
  constraints: repos=acme/tool perms=contents:write branches=cloop/*|feature/**
  expires:     2026-09-27T20:51:49Z (in 24h0m0s)
```

The project may now push `cloop/fix-42` and `feature/login/v2`, and nothing else:
not `main`, not `develop`, not a tag. The same list is the **Push to branches**
field on a project's Repository Access panel and in the Secrets panel's grant
and access-request dialogs. `cloop hub grant request --branches` asks for one.

**Patterns** name branches, with or without `refs/heads/`. `*` and `?` match
within one path segment, so `cloop/*` covers `cloop/fix-42` but not
`cloop/fix-42/retry`. A trailing `/**` covers any depth below its prefix, and
`**` alone is every branch. Patterns may use letters, digits, `-`, `_`, `.` and
`/`, within git's rules for branch names, and a list may have up to 32. A list
on a grant that can't push (`contents:read`, or a PAT grant with no
`--permissions`) is refused.

**Only the git proxy can enforce this.** Git's credential protocol never says
which branch a push is for, so nothing that holds the token (a helper script,
the sandbox, the workload) can keep it off `main`. The proxy can, because it
reads every command in a push before forwarding any of them. So what a branch
list does depends on the hub, and the dashboard shows it on every row:

| This hub | `github_app` grant with branches | `github_pat` grant with branches |
| --- | --- | --- |
| Runs the git proxy | Enforced: a push outside the list is refused by the proxy, outside the sandbox, and audited as `gitproxy.push_denied` | Same |
| Has `executors.git_proxy` enabled, but the proxy is not running | Not delivered: the lease fails closed, as every GitHub lease does on such a hub | Same |
| Has no git proxy | Delivered **read-only**: the installation token is minted with every permission capped at read, and GitHub refuses the push | **Not delivered**: a PAT can't be narrowed after it is issued, and delivering it would allow pushes to every branch it reaches |

No credential that could push anywhere is ever delivered with the list attached.
The lease's audit row says which case applied (`read-only: write withheld, …`
in its summary, or a denial naming `executors.git_proxy`), and so does the dry
run:

```console
$ cloop secret lease --project /srv/app
✗ deploy-pat (grant_f375eb24fcfb5a445d66ebb5) not delivered
    reason:      secretbroker: branch allowlist cannot be enforced without the git proxy: grant grant_f375eb24fcfb5a445d66ebb5 limits pushes to branches cloop/*, which only cloop's git proxy can enforce, and this hub runs none; a github_pat cannot be narrowed to read-only instead, so it is not delivered — enable executors.git_proxy, or grant without a branch allowlist
```

**Where the proxy runs, its own list is the upper limit.**
`executors.git_proxy.allowed_refs` (`refs/heads/cloop/**` unless the operator
widened it) is checked first, and a grant's branches narrow within it, so a
branch has to be in both. On a hub that kept the default, a grant listing `main`
gains nothing; the panel shows the hub's limit under the field. An operator who
wants projects to choose their own branches widens `allowed_refs` (for example
to `refs/heads/**`) and lets each grant say which.

**The agent is told.** The lease announces the grant's list in
`CLOOP_GITHUB_PUSH_BRANCHES` and the hub's in `CLOOP_GIT_PUSH_REFS`, and the
task prompt turns them into an instruction: which branches the agent may push
to, that anything else (including the default branch) will be refused, and an
example branch name that fits. A read-only delivery explains why in
`CLOOP_GITHUB_WRITE_WITHHELD`, and the agent is told to finish the rest of the
work and report the push it couldn't make instead of retrying it.

**Editing** an assignment's access or branches from the panel creates a new
grant and retires the old one (grants are immutable), keeping the old grant's
expiry. Both are audited. An edit that narrows the access or the branches takes
the old access back from a running task at once, and its next lease carries the
new terms. An edit that only widens leaves the run working with what it has
(see [Revoking a grant](#revoking-a-grant)).

**Every hub that leases from the control plane has to understand the list.** A
branch list is stored in the grant's constraints, and a cloop binary older than
the feature ignores it and treats the grant as one that may push anywhere. Keep
older hubs off a shared control plane, or away from projects whose grants have
branch lists, until they are upgraded. Edge agents aren't affected: they receive
a lease's materials, never a grant's constraints.

---

## Granting a PAT for workspace provisioning

Everything above is about what a running task can reach. This section covers an
earlier step. On an executor that doesn't share the hub's filesystem (a
Kubernetes Pod, an enrolled device), the project's source tree has to be fetched
before the harness starts. That fetch needs a credential too: the same
`github_pat` secret, delivered differently.

Inside the sandbox, the credential is a helper in a lease directory created for
the task. The workspace fetch happens before any of that exists. It runs in a
Kubernetes init container or as a pre-step on the device, and the token reaches
one `git fetch` process and nothing else: never the harness, never a file, never
an argv. See
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

Five things about that command matter:

- **The subject is the executor**, not the project. Either works, because the
  grant is matched against a requester carrying the executor id, its recorded
  labels and the project path. But the executor describes what is happening: a
  machine is being authorised to fetch a repository. A
  [label subject](#label-subjects) works too, for a fleet: a grant to
  `label:site=lab` lets every device labelled `site=lab`, and each virtual
  executor on one, fetch the repositories the grant admits.
- **`--repos` must admit the repository being cloned**, matched as `owner/name`
  against the same globs as above. This check keeps a workspace fetch inside
  its grant.
- **The origin must be on the secret's host.** An allowlist names `owner/name`
  and nothing else, so the host comes from the secret. A `github_pat` is a
  `github.com` token unless it was minted for a
  [GitHub Enterprise Server](#github-enterprise-server), and a `github_app`
  works on the web host of its `base_url`. A project whose origin is
  `https://git.example.org/acme/tool` is not authorised by a `github.com` grant
  for `acme/*`, even though its path matches: the run is refused, the error
  names both hosts, and the token goes nowhere. When comparing hosts, cloop
  ignores only differences that still reach the same server (letter case, a
  trailing dot, the default port, userinfo, an internationalised name's Unicode
  spelling). A different port, `github.com.example.net`, or a look-alike such as `gіthub.com`
  is a different host. Only `github.com` and GitHub Enterprise Server hosts
  receive brokered credentials. A repository on any other forge is fetched
  anonymously where no grant could apply (a path that isn't `owner/name`, as
  below), and otherwise refused with an error naming its host.
- **The remote must be an `https://` URL of the form `owner/name`.** cloop
  rewrites the scp form (`git@github.com:acme/tool.git`) and `ssh://` remotes
  automatically. `http://`, `git://` and local paths are refused, because a
  brokered token sent in cleartext is exposed, and the broker can't lease ssh
  access. A URL that isn't `owner/name` (a GitLab subgroup, say) can't be
  matched against a repository allowlist, so it is fetched anonymously instead
  of refused: no grant could have authorised it.
- **No `--permissions` is required.** The fetch is a read, and GitHub enforces
  whatever the PAT itself carries. It is still useful to set, because it is
  recorded in the grant and shows up in the audit trail.

Nothing else changes. The hub picks up the grant on the next run, records only
its name in the dispatched workload, and leases the material for the length of
one fetch.

### With the git proxy on, the token does not enter the sandbox at all

A hub with [`executors.git_proxy`](../git-interception-proxy.md) enabled leases
this grant as described above, then keeps the PAT. The sandbox gets a session
token for a proxy the hub runs, and its remote is rewritten to point at the
proxy. The clone and the write-back push both go through it, and the proxy
refuses any ref update outside `refs/heads/cloop/**`.

The grant stays the same: the same `--to executor:…`, `--repos`, matching and
audit rows, because the proxy's URL keeps the `owner/name` form the allowlist
is matched against. What changes is that a leaked sandbox token is good for one
namespace on one repository until its run is done with it, instead of being the
PAT.

Two things to know before you turn it on. A session lasts as long as its run: it
is renewed `session_minutes` (60 by default) at a time while the run lives, and
closed once the run is done with it. And the sandbox's git must trust the
proxy's certificate, which for a self-signed hub certificate means installing
the CA in the sandbox image. Both are covered in
[operating it](../git-interception-proxy.md#operating-it).

**The task's own GitHub grant goes through the proxy too, by a separate path.**
On such a hub, a GitHub grant made so the workload can reach repositories isn't
delivered as a token either: the lease hands the token to the proxy and the
sandbox gets a session scoped to that grant's allowlist, as
[the helper's limit](#the-helpers-limit-and-what-removes-it) describes. The two
grants stay separate: this one authorises cloop's own fetch of the project's
repository, the other whatever the workload's git does, and each mints its own
session. See
[two paths into one proxy](../architecture/git-proxy.md#two-paths-into-one-proxy).

### GitHub Enterprise Server

Mint a PAT issued by a GitHub Enterprise Server with its host. The host is
sealed together with the token, so editing the database row can't change it:

```console
$ cloop secret mint ghes-pat --kind github_pat --github-host ghes.example.com --file token.txt
$ cloop secret grant ghes-pat --to executor:k8s-prod --repos 'acme/tool' --ttl 24h
```

(The payload is then the JSON document `{"token": "…", "host": "ghes.example.com"}`,
which is also what the dashboard's Secrets panel accepts for one.) A `github_app`
on an Enterprise Server names its API in `base_url`
(`https://ghes.example.com/api/v3`), and its tokens work on `ghes.example.com`.
Either kind is presented only to its own server: never to `github.com`, even for
a repository with the same `owner/name`. A `github.com` grant is never presented
to the Enterprise Server either. With the git proxy on, the server's URLs reach
the proxy through their own route, so a lease holding grants for both hosts
keeps them apart (see
[the git proxy's forge routes](../architecture/git-proxy.md#one-route-per-forge-host)).

Upgrade every hub member that shares the control plane before you mint such a
PAT. A member on a build from before hosts were recorded reads the whole
document as the token, and presents it, Enterprise token included, wherever a
project's origin points.

### When it is missing

The run doesn't start, and the error says why. It is an HTTP 409 in the run
panel (`workspace_grant_missing`), and this on a terminal:

```
executor: cannot provision the workspace for /srv/acme on executor k8s-prod: no
active GitHub grant is issued to executor k8s-prod for this project, so
acme/tool cannot be fetched — grant one with: cloop secret grant
<github-pat-secret> --to executor:k8s-prod --repos acme/tool
```

Without this check, the harness would start in an empty directory and report
confidently on code it never read.

A grant that exists but excludes the repository gives a different message
("grant workspace-pat is issued to this executor but its allowlist excludes
repository acme/tool"), because the fix is different: widen `--repos` on the
grant you already have instead of running `cloop secret grant`.

A grant whose `--repos` admits the path, but on another host, gives a third
message, naming both hosts:

```
executor: cannot provision the workspace for /srv/acme on executor k8s-prod:
grant workspace-pat admits this repository's owner/name, but its credential is
for github.com and the project's origin is on git.example.org — a brokered
credential is never presented to a host other than its grant's — point the
project's origin at github.com, or authorise git.example.org with a credential
issued by it (…)
```

Widening `--repos` can't fix that one, because the host belongs to the secret,
not the grant. Either the origin is wrong (someone pointed it at another
server), or the repository really is elsewhere and needs a credential from
there.

Two more forms of the same failure:

| Message names | What it means |
| --- | --- |
| "the project has no origin remote" / "is a local path" | the project can't be fetched at all. Give it an https remote, or bind it to an executor that shares this host's filesystem |
| "cannot materialise a source tree" at *placement* | the executor can't fetch (a device with no `git`, or an agent below protocol v3). No credential is involved: upgrade the agent or move the project |

`cloop secret lease --project /srv/acme --executor k8s-prod` is the quickest way
to check that the grant is seen at all: if `workspace-pat` isn't in its output,
the workspace fetch won't see it either.

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

The cluster restriction is the strongest guarantee, because the document is
rewritten before it is delivered:

1. only contexts in `--contexts` are kept;
2. each remaining context is pinned to an allowed namespace. Its current
   namespace is kept if it is allowed; otherwise the first concrete (non-glob)
   allowed namespace is used, and if there is none the context is dropped;
3. clusters and users that no remaining context refers to are removed entirely,
   credentials included;
4. `current-context` is changed if its context was dropped.

A workload granted the `prod` context receives a kubeconfig with no server
address and no token for `staging`. It can't reach a cluster it wasn't granted,
whatever it does with the file.

Namespaces and read-only access are different. Step 2 pins a namespace into the
delivered context, but a `namespace:` in a kubeconfig is only the default
`kubectl` uses when you omit `-n`, and `kubectl -n kube-system get secrets`
ignores it. Verbs can't be written into a kubeconfig at all: the document
carries a credential, and what it can do is whatever the cluster's RBAC grants
its user.

Both are enforced by the [Kubernetes access monitor](../architecture/kubernetes-access.md),
which runs outside the sandbox and decides every API request before the cluster
credential is attached. Turn it on with `executors.kube_guard.enabled: true`
(`tls: auto`). Without the monitor nothing would enforce either, so a grant that
names `--namespaces`, or fewer than all eight verbs (including the read-only
default), is not delivered. The run goes without it and is told why on its
Activity tab, the Secrets panel marks the grant **no kube monitor: not
delivered**, and `cloop hub doctor` fails. If giving the workload the cluster
credential without enforcement is acceptable, an administrator records that on
the grant, with a reason:

```console
$ cloop hub grant unguarded grant_187bd292e8f8da691fa698ea --reason "lab cluster, monitor next sprint"
✓ grant_187bd292e8f8da691fa698ea may be delivered without the Kubernetes access monitor
  unenforced  namespaces team-a and read-only access (get, list, watch)
  recorded    by cli:root at 2026-10-12T14:02:11Z
  reason      lab cluster, monitor next sprint
```

Administrators can also use **Acknowledge unguarded** on the grant's row in the
Secrets panel. The acknowledgement is audited (`secret.unguarded_ack`), shown on
the grant wherever it appears, and withdrawn with `--withdraw` or **Withdraw
acknowledgement**. See
[without the monitor](../architecture/kubernetes-access.md#without-the-monitor-refused-unless-acknowledged).
A grant that names only contexts and every verb claims nothing a monitor would
enforce, so it is delivered without one.

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

### A cluster that signs you in through a plugin (AKS, EKS, GKE)

Managed clusters sign people in through an **exec credential plugin**:
`kubelogin` on AKS with Entra ID, `aws eks get-token` on EKS,
`gke-gcloud-auth-plugin` on GKE. The hub never runs one, because that would mean
running a program named in an uploaded file on the control-plane host, and a
sandbox has neither the plugin nor you to complete the sign-in. So the dashboard
refuses such a kubeconfig at upload, and names the plugin and the command to use
instead:

```
This kubeconfig cannot be stored: user "clusterUser_rg_aks-dev" (context aks-dev) signs in
through kubelogin (Microsoft Entra ID, as on AKS). … Share the cluster from your own
terminal instead: …

    cloop remote kube share aks-dev --hub https://cloop.example.com --context aks-dev --namespaces payments
```

`cloop remote kube share` runs on your machine, against your own kubeconfig,
over the terminal session [`cloop login`](../getting-started/terminal.md) gave
you. It runs the plugin there, where `kubectl` would, and leaves the hub holding
only a kubeconfig for a ServiceAccount that can do what you chose:

```console
$ cloop remote kube share aks-dev --context aks-dev --namespaces payments,payments-staging
Sharing context aks-dev (https://aks-dev-dns.hcp.westeurope.azmk8s.io:443) with https://cloop.example.com as "aks-dev":
  ServiceAccount  payments/cloop-aks-dev-3f9c2a1b (no token mounted into Pods)
  Read access     payments, payments-staging (RoleBinding cloop-aks-dev-3f9c2a1b -> ClusterRole view in each)
  Self-renewal    Role cloop-aks-dev-3f9c2a1b-renew in payments: create serviceaccounts/token for cloop-aks-dev-3f9c2a1b only; the hub's Kubernetes monitor refuses it to every sandbox
  Token           1d, through the TokenRequest API
Signing in to https://aks-dev-dns.hcp.westeurope.azmk8s.io:443 with kubelogin (Microsoft Entra ID, as on AKS)…
The cluster knows you as alice@example.com.

Shared. https://cloop.example.com holds the token as your personal secret "aks-dev" (sec_9b1f…).
  Token expires   2026-10-13 09:14 UTC (in 23h59m)
  Renewal         by the hub, at half the token's life; `cloop remote kube list` shows it
```

| It creates | Why |
| --- | --- |
| A **ServiceAccount**, labelled `cloop.dev/kube-share=<id>`, with `automountServiceAccountToken: false` | The identity the hub holds a token for. Nothing should run as it |
| A **RoleBinding** in each `--namespaces` entry to the cluster's `view` role (`edit` with `--access write`) | The access, in those namespaces only. A ClusterRoleBinding only with `--cluster-wide`, and then read-only |
| With hub renewal, a **Role** allowing `create` on `serviceaccounts/token` with `resourceNames: [<the ServiceAccount>]`, and its RoleBinding | How the hub mints the next token. See below |
| A **token**, through the TokenRequest API, for `--ttl` (10 minutes to 7 days, default 24h) | Limited, and possibly shorter: managed API servers cap it, and the command says when |

On a hub with single sign-on the secret is personal to you (`--shared` stores
an organisation secret, which needs `secret.grant`). Grant it to a project like
any kubeconfig, from the Secrets panel or with
`cloop secret grant aks-dev --to project:<path> --namespaces payments` on the
hub, keeping the grant's namespaces inside the share's.

**A write share's ServiceAccount lives where it can't write.** The `edit` role
may create Pods and Secrets and mint tokens in its namespace. A ServiceAccount
that can write to its own namespace could hand a workload its credential in
several ways (a Pod running as it that prints its token, a token Secret for
it), none of which goes through the monitor or ends with the share's TTL. So
`--access write` needs `--sa-namespace`, a namespace you control that isn't
among `--namespaces`, and is refused without it. Cluster-wide write is always
refused. Read access binds `view`, which can read neither Secrets nor the logs
of a Pod it could have started, so a read share's ServiceAccount lives in the
first shared namespace unless you choose otherwise.

**Renewal.** Managed API servers cap how long a token lives, which used to make
projects stop working mid-run for no clear reason.

- *The hub renews it* when the hub runs the
  [Kubernetes access monitor](../architecture/kubernetes-access.md#kubernetes-shares-a-cluster-behind-a-credential-plugin)
  (`--renewal auto`, the default, picks this; `cloop remote kube list` says
  which the hub does). At half the token's life, one hub process mints the next
  token with the share's own self-renewal Role and stores it in place (same
  secret, same grants), and every running monitor session switches to it within
  a minute. So a run dispatched before the renewal keeps working after its first
  token has expired. The monitor refuses the `serviceaccounts/token`
  subresource to every sandbox under every grant, so only the hub can use that
  permission. Each renewal is a `secret.renew` audit row naming both expiries.
- *You renew it* otherwise. Without the monitor the token sits in the sandbox,
  so no self-renewal Role is installed (`--renewal manual` asks for this on any
  hub). `cloop remote kube renew aks-dev` mints the next token with your own
  credentials (through the plugin again) and hands it to the hub, which checks
  with the cluster that it belongs to the share's ServiceAccount before storing
  it. A run that already holds the old kubeconfig keeps it until that token
  expires, and the next dispatch gets the new one.

A self-renewing share is only ever delivered through the monitor. Its
ServiceAccount may mint its own tokens, so as a file in a sandbox it would be a
credential that can extend itself. If the hub's monitor is turned off later, its
grants are refused at dispatch with that reason, and the run is told as
described below.

```console
$ cloop remote kube list
https://cloop.example.com runs the Kubernetes access monitor: it renews the shares made for it.
NAME     SERVICE ACCOUNT                    NAMESPACES                 ACCESS  EXPIRES                         RENEWAL               GRANTS
aks-dev  payments/cloop-aks-dev-3f9c2a1b    payments,payments-staging  read    2026-10-13 21:14 UTC (in 23h)   hub, renewed 1h ago   2

$ cloop remote kube renew aks-dev          # the hub renews now; --local mints with your credentials
$ cloop remote kube revoke aks-dev
Deleted ServiceAccount payments/cloop-aks-dev-3f9c2a1b
Deleted RoleBinding payments/cloop-aks-dev-3f9c2a1b
…
Deleted secret aks-dev from https://cloop.example.com, revoking its 2 active grant(s).
```

`revoke` first asks the hub whether you may revoke the share, and changes
nothing if not. It then deletes the ServiceAccount, which invalidates every
token ever minted for it (the hub's and any copies), then its bindings and Role,
then the hub's secret, which revokes its grants and closes the monitor sessions
using it. It deletes only objects it reads back from the cluster with the
share's `cloop.dev/kube-share` label and an owner annotation naming the share's
owner. Anything else it was pointed at is reported as `Not deleted, not
this share's` and left alone. `revoke` and `renew` also refuse a context that
doesn't reach the share's own API server through the CA the share trusts (pass
`--context` to name one that does), and `renew` mints only for a ServiceAccount
it reads back as the share's. If the cluster can't be reached or an object
can't be deleted, the secret is kept so you can run the revoke again. `--force`
deletes it anyway and names what is left of the share's own objects, or lists
the candidates with their owner for you to check before deleting anything.

The hub renews a personal share only while its owner may use the hub. If the
owner is suspended at the identity provider, or offboarded with the secret kept
under a legal hold, renewal stops, and `list` says why.

Deleting the secret on the hub instead (from the Secrets panel, or because its
owner was [offboarded](#when-the-owner-of-a-personal-secret-leaves)) destroys
the hub's copy of the token and revokes the grants. The hub has no permission to
delete anything in the cluster, though, so the ServiceAccount and its bindings
stay until somebody removes them, and the token the hub held lapses when it
expires. `cloop remote kube revoke` on a share the hub no longer has prints the
`kubectl` commands that find and remove them by label.

| Flag | Does |
| --- | --- |
| `--context`, `--kubeconfig` | Which context of which kubeconfig (default: kubectl's) |
| `--namespaces a,b`, `--access read\|write`, `--sa-namespace`, `--cluster-wide` | What the ServiceAccount may reach, and where it lives |
| `--ttl 24h` | The token's life, 10m to 7d |
| `--renewal auto\|hub\|manual` | Who renews it |
| `--server https://…` | The API server address the hub uses, if it reaches the cluster at a different address from you (a private endpoint) |
| `--dry-run` | Print the plan, sign in to nothing, create nothing |

### Several kubeconfig grants on one project

A project can hold more than one kubeconfig grant: two clusters, one cluster
granted twice for different namespaces or verbs, or an edited assignment whose
predecessor isn't revoked yet. They are delivered together, as one merged
kubeconfig with a context per grant:

```console
$ cloop secret grant prod-kube --to project:/srv/app --namespaces team-a --ttl 12h
$ cloop secret grant prod-kube --to project:/srv/app --namespaces team-b \
    --verbs get,list,watch,create --ttl 2h
$ cloop secret grant staging-kube --to project:/srv/app --contexts staging --ttl 12h
```

```
files:  kubeconfig   0600            one document, three contexts
env:    KUBECONFIG=<lease dir>/kubeconfig
        CLOOP_K8S_CONTEXTS=prod-kube,prod-kube-2,staging-kube
        CLOOP_K8S_GRANTS=[{"contexts":["prod-kube"],"secret":"prod-kube","namespace":"team-a",…},…]
        CLOOP_KUBEGUARD_SESSIONS=<session id>,<session id>,<session id>
        CLOOP_K8S_NAMESPACE=team-a          the grant behind current-context
        CLOOP_K8S_ALLOWED_NAMESPACES=team-a
        CLOOP_K8S_VERBS=get,list,watch
        CLOOP_KUBEGUARD_SESSION=<session id>
```

- **Names.** Each grant's cluster, user and context are named after its secret,
  in lower-case letters, digits and `-` (so `kubectl --context prod-kube` needs
  no quoting), with a `-2` or `-3` suffix when another grant took the name
  first, as for the second grant of `prod-kube` above. A grant whose kubeconfig
  keeps several contexts (no monitor, several allowed) names each after its
  own: `corp-staging`, `corp-production`.
- **`current-context` belongs to the narrowest grant**, so a `kubectl` command
  that names no context reaches as little as possible. Grants whose namespaces
  are all named come before ones a pattern admits, which come before
  cluster-wide ones; then read-only before read-write; then fewer namespaces
  first; then by secret name.
- **The variables.** With one grant they are as above. With several, the
  single-grant variables describe the grant behind `current-context`, and three
  more describe every grant. `CLOOP_K8S_CONTEXTS` lists the contexts,
  `current-context` first. `CLOOP_K8S_GRANTS` is a JSON array with each grant's
  contexts, secret, pinned and allowed namespaces, verbs, and whether the
  monitor holds it and under which session. `CLOOP_KUBEGUARD_SESSIONS` lists the
  sessions. None of them is a credential.
- **Revoking one of them** takes back that grant's access and leaves the others
  working, as long as the monitor holds it: its context in the document carries
  only a session token, and revoking the grant closes that session. A grant the
  monitor doesn't hold has its cluster credential in the document itself, and
  no delivery path can cut that out of a file the workload may have open. So
  revoking it takes the whole document, and the run has no Kubernetes access
  until its next dispatch. The same happens when every grant is monitored and
  you revoke the one the document is filed under (the narrowest). Both cases err
  towards less access. On a container or Pod, revoking a grant that set
  variables removes the workload, as described [below](#revoking-a-grant).

Older builds wrote every kubeconfig to the same `kubeconfig` path, so a project
holding two couldn't run on any executor that receives files
(`secret_files[N] repeats path …/kubeconfig`), and on the hub one document
replaced the other without an error. `cloop secret lease` adds a **delivered as
one directory** section whenever grants are merged, naming the single file and
every variable the workload gets.

### When a run goes without a kubeconfig it was granted

A grant can be in place and its secret exist, and the broker can still refuse to
deliver it:

- the Kubernetes monitor is required (`executors.kube_guard.enabled: true`) but
  isn't running;
- the monitor refuses a kubeconfig whose user runs an `exec` plugin (AKS
  `kubelogin`, EKS, GKE) or an `auth-provider`. The dashboard refuses such a
  kubeconfig at upload; one stored before that check, or minted with
  `cloop secret mint` on the hub, is refused here;
- a [self-renewing share](#a-cluster-that-signs-you-in-through-a-plugin-aks-eks-gke)
  meets a hub without the monitor;
- the payload no longer parses as YAML;
- no context is left after the grant's `--contexts` and `--namespaces`.

The run starts without it. The refusal is shown on the lease and written to the
project's **Activity** tab as a `credential_refused` event on every run it
affects, naming the run: `This run
goes without kubeconfig "aks-kube", which the project was granted, because the
hub could not deliver it: credential guard unavailable: … exec credential
plugin …`. A grant [refused because there is no monitor](#kubeconfig) is
reported the same way, naming `cloop hub grant unguarded`. So is every other
kind the broker refuses like this: a GitHub token the git proxy couldn't take,
or an App token GitHub wouldn't mint. A credential whose secret was destroyed is
reported once per hub process instead
([below](#when-the-owner-of-a-personal-secret-leaves)), since nothing will bring
it back.

---

## Container registries

```console
$ cloop secret mint ghcr-login --kind registry --file ~/.docker/config.json
$ cloop secret grant ghcr-login --to label:region=eu --registries ghcr.io --ttl 24h
```

The docker config is filtered to the allowed registries, and auth entries for
everything else are removed. A `user:password` payload is wrapped into a
`config.json` for the first allowed registry. It is delivered as
`DOCKER_CONFIG`, pointing at the lease directory.

---

## Environment secrets

```console
$ printf '{"API_KEY":"abc","WEBHOOK_SECRET":"def"}' | cloop secret mint app-env --kind env
$ cloop secret grant app-env --to project:/srv/app --env-keys API_KEY --ttl 8h
```

Only the allowlisted keys are set in the workload's environment, and the rest
are dropped. Without `--env-keys`, every key in the secret is delivered, which
is fine when the secret holds only what the workload needs.

**The payload is a JSON object of names to values.** Anything else is one value,
delivered under a name derived from the secret's name. `KEY=value` lines piped
into `cloop secret mint app-env` become a single variable `APP_ENV` holding all
of them, and a grant limited to `API_KEY` then delivers nothing;
`cloop secret lease --project /srv/app` says so (*env secret app-env has no key
matching API_KEY*). Use the bare form for a single value whose name the secret's
name already spells: `cloop secret mint anthropic_api_key --kind env` delivers
`ANTHROPIC_API_KEY`.
Through `POST /api/secrets` the object is itself a JSON string, so it is encoded
twice: `"payload": "{\"API_KEY\":\"abc\"}"`.

### The Claude credential of a sandboxed run

A `claudecode` project whose executor isolates it from the host (a container, a
Pod, an enrolled device or a virtual executor on one) gets no Claude login from
the hub.
[It isn't given a configuration directory](../security/claude-code-identity.md#isolating-executors-do-not-get-a-directory),
and the hub's own login never leaves the hub. Its harness signs in with one of
these, delivered by a grant:

| Provider | Any one of |
| --- | --- |
| `claudecode` | `CLAUDE_CODE_OAUTH_TOKEN` (from `claude setup-token`), `ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN` together with `ANTHROPIC_BASE_URL` (a gateway), or `CLAUDE_CODE_USE_BEDROCK` / `CLAUDE_CODE_USE_VERTEX` (the cloud's own credentials beside it, in the secret or the machine's role) |
| `anthropic` | `ANTHROPIC_API_KEY` or `CLOOP_ANTHROPIC_API_KEY`, or `anthropic.api_key` in the project's `config.yaml` on a container executor, which reads the project's tree |
| `copilot` | `COPILOT_GITHUB_TOKEN` (a fine-grained GitHub token with the Copilot Requests permission, or an OAuth token), or `COPILOT_PROVIDER_BASE_URL` (a model provider of the project's own, with its key beside it). `GH_TOKEN` and `GITHUB_TOKEN` do not count: a repository grant puts tokens there that need not carry Copilot access, and the CLI reads `COPILOT_GITHUB_TOKEN` before them |

Other providers aren't checked. Nor is a host executor, which runs the harness
under the hub's or the requesting user's own login, with one exception: a
`copilot` project on a hub with single sign-on signs in there only with a
credential granted to the project that counts for the person running it, never
the hub's own (see [per-person Copilot credentials](../security/copilot-identity.md)).
The provider checked is the one the sandbox will run. A container on the hub's
tree reads the project's `config.yaml`, then its state, and none of the hub's
environment. A device or a Pod reads the `config.yaml` committed in its
repository, if there is one, and otherwise the provider in the state the hub
seeds it with, which is the hub's own choice for the project: its
`config.yaml`, the hub's `CLOOP_PROVIDER`, then its state. Where the hub can't
tell which of the two a device will read, it doesn't refuse based on a guess.
List an executor that brings its own credential (a device signed in to `claude`
as its agent user, an image with a key built in) in the hub's
[`executors.harness_credential_exempt`](../reference/configuration.md#executors-that-bring-their-own-claude-credential).

**The hub checks before it dispatches.** A run, an automatic resume, a
brainstorm or plan from the Tasks tab, an assistant message and a reproduction
are all refused, without starting a workload, if the lease the sandbox would get
carries none of the above, or if the sandbox would lose it within ten minutes,
before a run could finish its first task. The refusal is a `409`:

```json
{
  "code": "harness_credential_missing",
  "error": "No active grant gives app's sandbox on executor sgx (remote) a Claude credential (…): a sandbox has no Claude login but what is granted to its project.",
  "remediation": "Open the project's Overview and use Claude credential to grant …",
  "executor_id": "sgx",
  "executor_kind": "remote",
  "provider": "claudecode",
  "needed": [["CLAUDE_CODE_OAUTH_TOKEN"], ["ANTHROPIC_API_KEY"], ["ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL"],
             ["CLAUDE_CODE_USE_BEDROCK"], ["CLAUDE_CODE_USE_VERTEX"]]
}
```

`harness_credential_expiring` also carries `expires_at`. The check predicts the
lease exactly: the same grants (a feature uses its parent project's), the same
`--env-keys` narrowing, the same `.cloop/sandbox.yaml` `env:` list, which
forwards only the variables it names (a granted token the list leaves out is
named in the refusal), and the same end time. A lease ends when the first of its
grants expires, whatever kind that grant is, so a GitHub grant ending in five
minutes takes a thirty-day Claude credential out of the sandbox with it. The
refusal names that grant, and the card shows the lease's expiry. A grant that
lapsed is named too. The ten-minute margin only covers the start: a run that
outlives its lease loses the credential then, so grant for the length of the
work, including for an auto-evolving project.

**Granting a credential.** On the project's Overview, a *Claude credential* card
(*Copilot credential* for a `copilot` project) appears next to the Executor card
whenever the executor isolates. For a `copilot` project on a hub with single
sign-on it also appears for the hub's own host, showing the viewer's own
credential, because each person's runs there need one that counts for them
([per-person Copilot credentials](../security/copilot-identity.md)). The card is
green with the credential's expiry, amber within three days of it, and red when
there is none.

The card opens a dialog, and so does a Run refused for this reason. The dialog
offers the env secrets you could grant (your own, and shared ones if you hold
`secret.grant` on the project) by name and by the key names they hold. You can
also paste a token from `claude setup-token` or an Anthropic API key or, for a
`copilot` project, a GitHub token the Copilot CLI signs in with (`github_pat_…`,
`gho_…` or `ghu_…`). A classic `ghp_…` token, which the CLI refuses, and
installation and refresh tokens, which act for no one with a seat, are refused
with the reason. A pasted token is checked against the
[credential registry](../reference/credential-patterns.md) that every scanner in
cloop shares, stored as a personal `env` secret holding that one key (a shared
one on a hub without single sign-on), and granted to the project. It is never
echoed, logged or stored anywhere but the secret store, and the field is cleared
as the request is sent.

Grants made here last 30 days unless you choose another lifetime, within the
90-day limit on every grant the dashboard makes, and carry the scope
`claude-credential`. Granting again for longer revokes the dialog's earlier
grants to the project, of the same owner's (or shared) secrets, that end sooner,
because they would otherwise end the lease first; the response lists them under
`superseded`. A Copilot credential never supersedes a Claude one, or the
reverse, so a project that changes provider keeps the grant it would need to
change back. Grants made from the Secrets panel or the CLI are left alone. The
dialog grants by narrowing a secret to the keys the harness reads, so grant a
Bedrock or Vertex secret, which has to be delivered whole, from the Secrets
panel.

The same through the API:

```console
$ curl -s -H "Authorization: Bearer $TOKEN" https://hub.example/api/projects/0/harness-credential
{"state":"missing","applies":true,"executor":{"id":"sgx","kind":"remote","isolates":true},
 "needed":[["CLAUDE_CODE_OAUTH_TOKEN"],["ANTHROPIC_API_KEY"],["ANTHROPIC_AUTH_TOKEN","ANTHROPIC_BASE_URL"],…],
 "satisfied_by":null,"candidates":[{"id":"sec_…","name":"team-claude","keys":["CLAUDE_CODE_OAUTH_TOKEN"],
 "complete":true,"personal":false,…}],…}
$ curl -s -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
    -d '{"secret":"team-claude","ttl_minutes":43200}' \
    https://hub.example/api/projects/0/harness-credential
```

`POST` takes either `{"secret": …}` (an env secret's id or name, optionally with
`env_keys` to choose among the keys it holds) or `{"token": …}` with an optional
`name`, never both. Reading the card needs `project.read`. Granting needs
`secret.own` on the project, plus `secret.grant` for a shared secret, and only
its owner can grant a personal secret. Both the mint and the grant are audited
like any other (`secret.mint`, `secret.grant`). `{idx}` is the project's index
in your project list, as for every `/api/projects/{idx}` route.

**On a hub with single sign-on, a personal Claude credential is only used for
runs its owner starts.** Granting your own token to a project you share doesn't
let the other members run on your subscription: their runs don't count it, and
only its owner's leases get it (not a run on the host, a pull request, or a
reproduction's test suite). Each other lease records a `secret.lease` denial
naming the grant and the reason. A member who needs a credential grants their
own, or a maintainer grants a shared secret. An automatic resume acts for
whoever started the run it resumes, as the hub recorded at dispatch. Other kinds
of personal secret are unaffected and reach the project's runs whoever starts
them.

From a shell on the hub, do the same with a mint and a grant. Run
`claude setup-token` wherever you are signed in to Claude, then run the
following, which keeps the token out of your shell history and the process
table:

```console
$ read -rs CLAUDE_TOKEN    # paste the sk-ant-oat01-… token, then Enter
$ printf '{"CLAUDE_CODE_OAUTH_TOKEN":"%s"}' "$CLAUDE_TOKEN" | cloop secret mint claude-code --kind env
$ unset CLAUDE_TOKEN
$ cloop secret grant claude-code --to project:/srv/app --env-keys CLAUDE_CODE_OAUTH_TOKEN --ttl 720h
```

### With the model relay on, the Claude credential stays on the hub

On a hub with [`executors.model_relay`](../reference/configuration.md#the-model-relay-for-sandboxed-runs)
on, the grant above still decides whether a run may start and whose credential
it uses (the pre-dispatch check is unchanged), but a Claude OAuth token it names
never enters the sandbox. The sandbox gets a relay session instead:

| Variable | Value |
| --- | --- |
| `ANTHROPIC_BASE_URL` | the relay, e.g. `https://hub.internal:8443/_anthropic` on the git proxy's listener |
| `ANTHROPIC_AUTH_TOKEN` | a `cloop_relay_…` session token, good for this run's model calls and nothing else |
| `CLOOP_MODEL_RELAY` | the session's id, as the run's history and the audit trail name it |
| `NODE_EXTRA_CA_CERTS` | under `tls: auto`, a file holding the hub's CA and nothing else |

`CLAUDE_CODE_OAUTH_TOKEN`, `ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN` and
`ANTHROPIC_BASE_URL` from the lease are removed from the environment first. The
session token is marked sensitive, so it is scrubbed from the run's output and
never stored with the dispatch. Claude Code sends its calls to the relay, which
makes them against the API with the credential and streams the answers back.

The session depends on the run's lease. It ends when the run does, and
immediately when the lease or its grant is revoked: the run's next model call is
then refused with `403` and the reason (`this run's model relay session has ended: grant
grant_… revoked by alice@corp.example`). Claude Code reports this and stops,
instead of retrying for three minutes as it does after a `401`. A hub restart
doesn't end the session: the process that adopts the run restores it with the
lease, deriving the credential again from the grant, and any call the sandbox
makes in the meantime waits.

**The relay counts what it costs.** Each response's usage (input, output, cache
reads and cache writes, as the API reports them) is priced and charged to
whoever started the run, against their `daily_token_budget` and
`daily_cost_usd`, as the call completes. A call made after a budget is spent is
refused before it reaches the API:

```text
API Error: 403 the daily token budget (daily_token_budget) of 100000 tokens for
alice@corp.example is spent: 132396 tokens used today. The model relay refuses
this run's calls until it resets at 00:00 UTC or an administrator raises it
```

When the run ends, the hub compares what the run reported to its project's
ledger with what the relay counted. The difference is booked to the ledger as
*Model relay: usage measured beyond what the run reported*, written to the run's
history, audited as `model_relay.usage_gap` and counted in
`cloop_model_relay_usage_gap_tokens_total`. `claudecode` runs report no tokens
of their own, so for them the relay's count is the whole bill.

**The card shows whether a credential is relayed.** The project's *Claude
credential* card reads *through the hub relay* under the credential's expiry,
and its dialog lists the models the project's runs may call: the hub's
allowlist, which a maintainer can narrow for the project but not widen. A call
for any other model is refused before it reaches the API (`model_not_allowed`).
A credential the relay doesn't handle yet (an Anthropic API key, until it has
been tested through the relay against the real API) reads *not relayed*, with
the reason. Such a run gets its credential as it would without the relay, and
its history and the `model_relay.not_relayed` audit row say so. The same applies
to a run on a device whose agent is older than protocol v23, when the relay
needs the agent to hand the harness the hub's CA; upgrade the agent to relay its
runs.

From the run's history on the project's Overview:

```text
Model calls go through the hub's relay (session 3f2a…): the Claude OAuth token
stays on the hub, and what the API reports spending is charged to the identity
"alice@corp.example". Models: claude-haiku-*.
…
The model relay counted 65,056 tokens ($0.05) for this run from the API's
responses; the run reported 0 tokens ($0.00). The identity
"alice@corp.example" was charged the relay's count, and the project's ledger now
carries the difference.
```

---

## Local git repositories

Every other kind gives a workload bytes. This one gives it paths: a directory on
the hub host holding git checkouts, opened to one project as bind mounts. It is
for a developer who has three repositories on the machine the hub runs on and
wants one project to build against them.

It is a grant, not a [`.cloop/sandbox.yaml`](../reference/sandbox.md) mount,
because that file is committed to the repository and a pull request can change
it. That is why `mounts.source` there is relative to the workspace and can't
name a host path. Here, a person holding `secret.grant` names the root, the
repositories and the project, outside the repository. So it gets the same
properties as every other grant: one subject, a TTL, an audit row naming who
opened it, and revocation that takes effect within a lease period instead of at
the end of the run.

```console
$ cloop secret mint local-src --kind local_repo --value /home/dev/src
✓ minted local-src (local_repo) as sec_8f2cca804195c0b73296b674
  no grant yet — nothing can use it until you run 'cloop secret grant'
```

The payload is an absolute path on the hub to a directory containing git
repositories. A root that is itself a repository is accepted too, so a single
checkout needs no wrapper directory. `--value` is fine here, because the payload
is a path, not a credential.

The root is stored once, and each grant opens a different part of it to a
different project, so with five projects and twenty checkouts each project gets
only the repositories it needs:

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

**`--repos` is required, and it is matched differently from a PAT's.** It
matches the repository's directory name directly under the root, not
`owner/repo`: `api-service` is exact, `shared-*` is a glob, and `*` is every
repository under the root. Only direct children count, so a root of `/home/dev`
doesn't reach a checkout at `/home/dev/.cache/dep/vendor/x`. Entries that aren't
git repositories, and entries whose names begin with a dot, are skipped. One
grant may open at most 32 repositories. A grant that would open more is refused,
not truncated.

Omitting it is refused at creation, not at delivery:

```console
$ cloop secret grant local-src --to project:/srv/app
Error: secretbroker: invalid constraint: a local_repo grant needs a repository
allowlist (--repos my-service, or --repos '*' for every repository under the root)
```

So is an allowlist that matches nothing. Otherwise the harness would only find
out several minutes in, from an empty `/repos`.

### What the sandbox actually gets

Repositories appear under `/repos`. The path is fixed, so a harness, a setup
script and a README can all refer to it without knowing which executor they run
on. It is outside `/workspace` because the workspace is bind-mounted whole, and a
target inside it would be hidden by that mount on some drivers but not others.

```
mounts: /home/dev/src/api-service   ->  /repos/api-service    read-only
        /home/dev/src/shared-proto  ->  /repos/shared-proto   read-only
env:    CLOOP_LOCAL_REPOS=api-service,shared-proto
        CLOOP_LOCAL_REPO_ROOT=/repos
        CLOOP_LOCAL_REPO_API_SERVICE=/repos/api-service
        CLOOP_LOCAL_REPO_SHARED_PROTO=/repos/shared-proto
```

The broker sets `CLOOP_LOCAL_REPOS`, which is correct whatever the driver does.
The path variables are added later, by the caller that holds both the lease and
the executor, because where the repositories end up depends on the driver, not
the grant (see below). A repository whose name doesn't map to a unique variable
name (`my-api` and `my.api` would both become `CLOOP_LOCAL_REPO_MY_API`) gets no
path variable, instead of one pointing at whichever grant was processed last. It
is still mounted and listed in `CLOOP_LOCAL_REPOS`.

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

Anything under the root that the allowlist doesn't match, or that isn't a git
repository, is missing from that list. Both checks run against this host, so a
mistyped glob shows up here instead of in the middle of a run.

### Read-only by default

`writable` is the one constraint that widens access instead of narrowing it, so
it is a bool that defaults to the safe value: a grant that doesn't set it
delivers a read-only bind. `Constraints.ValidateFor` refuses it on every other
kind ("writable applies to local_repo grants, not `github_pat`").

Usually a sandbox only needs to read a developer's checkout (build against it,
grep it, copy from it), and a read-only bind means a runaway harness can't
rewrite the history of a repository that exists nowhere else. A project that
needs to commit asks for write access.

A read-write grant is `--writable` on the CLI, `"writable": true` on the API, or
a checkbox on the dashboard's grant form, which is offered only for
`local_repo`:

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

A read-write grant shows `writable` in its constraint summary, in
`cloop secret grants` and in every audit row. A read-only grant shows nothing
there, because read-only is the default.

### Not every executor can receive it

Some executors refuse this grant outright, so read this before you rely on it.
(The other such refusal is `secret_files`, for an executor that can't receive a
lease's files; see
[Secret file delivery](../architecture/executors.md#secret-file-delivery). This
one is for an executor that can't reach the hub's filesystem at all, which no
protocol upgrade fixes.) The same grant reaches a workload in three different
ways, depending on the driver:

| Executor | What happens | `SupportsHostMounts` |
| --- | --- | --- |
| `container` (including Kata) | each repository is bound at `/repos/<name>` | ✅ |
| `localprocess` | no mounts at all: it shares the hub's filesystem, so the repositories are already visible at their own paths, and the environment names those paths | ❌ (`SharesHostFilesystem` covers it instead) |
| `kubernetes`, `remote` | **refused** | ❌ |

Kubernetes and remote-agent executors run on a machine that has never seen these
files, so the grant can't be delivered and the run doesn't start:

```
executor: invalid spec: executor k8s-prod (kubernetes) cannot receive
repositories from the control-plane host, but this project holds a local_repo
grant for api-service, shared-proto. Bind the project to a container or Kata
executor running on the hub, or publish the repositories over https and grant a
github_pat instead
```

It is an error, not a warning, because this is the moment when "I granted my
checkouts to this project" and "I bound this project to a remote sandbox" turn
out to be incompatible, and the person who needs to know is the one who just
pressed Run. Otherwise the harness would start anyway and report that the
repository is empty.

On `localprocess`, `writable: false` is not enforced. The harness runs as the hub
user against the repositories' real paths, so it can write to them whatever the
grant says, and cloop logs a line saying so at start. That driver already has
the whole filesystem (it is the one an operator turns off first, with
`executors: allow_host_process: false`), so there the grant only tells the
harness where the repositories are. Bind a container executor if read-only has
to be enforced.

`SharesHostFilesystem` doesn't imply `SupportsHostMounts`, as the middle row of
the table shows: `localprocess` shares the filesystem but can bind nothing. Only
a driver that runs on the hub and has a mount namespace to bind into can support
host mounts. When a spec with host mounts is placed or failed over across a
fleet, the same requirement is called `host_mounts`; see
[Placement](../architecture/executors.md#placement).

### Revocation releases it at the end of the run

Revoking a `local_repo` grant works differently from revoking a token. A revoked
lease's files are wiped and its environment variables scrubbed, but a bind mount
already in a running sandbox's mount namespace can't be taken back from outside.
The grant is removed from the run's lease at once and never issued again, so no
new run gets the repository, but the run that already has the bind keeps it
until it exits.

To cut access to a repository immediately, stop the workload with the
dashboard's Stop button, or revoke the run's lease with `action=kill` from the
Secrets panel. [Cordoning the executor](../architecture/executors.md#placement)
doesn't help, because it only stops new work. There is no top-level
`cloop stop` command.

### Containment

The operator names a root, and nothing under it may redirect the bind outside
it. This rests on one rule: every candidate path is resolved with `EvalSymlinks`
and checked again against the resolved root. A symlink planted at
`<root>/evil -> /` resolves to `/`, which isn't under the root, so it is
dropped, whoever created the link. Containment is checked with `filepath.Rel`,
not a string prefix, so a root of `/home/dev/src` doesn't also admit
`/home/dev/src-other`.

Paths are resolved once, when the lease is issued, and the driver binds the
resolved path. The container driver doesn't resolve again, since it no longer
knows the root to check against. That leaves a window between issuing the lease
and starting the sandbox, in which someone who can write to the granted root
itself could swap a path component. A sandbox holding a read-only grant can't do
this (it can write inside a repository, but not to the directory that holds
it), so the risk comes from something already running as the developer on the
hub. Don't grant a root that untrusted processes can write to.

Resolving first also makes symlinked checkouts work, which is how many people
arrange a source tree: the link is followed, and then the result has to be
inside the root. A root that is itself a symlink is fine for the same reason: it
is resolved before anything is compared against it.

Names are checked separately from paths. A directory name containing a colon
would add mount options, or a third path, to the container runtime's `-v` flag.
A name that is `.` or `..`, or contains a slash, a backslash, a NUL or a newline,
wouldn't be a direct child at all, and a name over 128 characters is refused. An
entry that fails these checks is skipped instead of failing the lease, because
it is a problem with the directory's contents, not with the grant. Otherwise
anyone who can write to the root could break an unrelated project's runs by
creating a file there. The check runs again immediately before a driver receives the
mount, because the two moments can be separated by a round trip to the store,
and this is the only material kind that puts a host path unchanged into a
runtime flag.

Revocation needs one more step here. The hub can scrub a credential file, but it
can't take a bind back, because it can't reach into a running sandbox's mount
namespace. The driver has to unbind, so the mounts are recorded on the lease.

---

## Host devices

`local_repo` gives a workload paths. This kind gives it hardware: device nodes on
the executor's host, opened to one project. It is for a bench with instruments
on serial lines, a machine with a GPU, or a task that needs `/dev/net/tun` to
create an interface of its own.

It is a grant for the same reason `local_repo` is, and the reason weighs more
here. A device node gives control over part of the machine: `/dev/ttyUSB0` is a
serial line into whatever is plugged in, and `/dev/nvidia0` is a compute unit
with its own memory and its own history of sandbox escapes. The file that would
otherwise carry it, [`.cloop/sandbox.yaml`](../reference/sandbox.md), is
committed to the repository. A `devices:` key there that could name
`/dev/anything` would hand the hardware to anyone whose pull request is merged,
so that file has no key that takes a path. Instead the operator owns the
inventory and the project owns the selection: `capabilities.devices` picks by
name from what the project already holds, and can only pick fewer.

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

One entry per line: `name=/dev/source[:/dev/target][:mode]`. The mode is `r`, `rw`
or `rwm`, and defaults to `rw`, which makes a device usable while still
withholding `mknod`. A second path in the middle field remaps the node, which
makes a grant portable: a project told it has `accel` doesn't need to know that
this host enumerates the card as `nvidia0`. Blank lines are skipped and a line
beginning with `#` is a comment, so the inventory can keep its annotations and
live in configuration management. At most 256 lines are read: a host's grantable
hardware is a short list, and parsing an unlimited one on a path an operator's
browser can reach would let anyone exhaust the hub's memory.

Everything downstream (the grant's allowlist, the sandbox spec, the audit row)
refers to a device by its name, so names follow the same rules as repository
names: at most 64 characters, and no colon, slash, backslash, equals sign,
space, NUL or newline. Two entries may not share a name or a sandbox-side
target. Otherwise argv order would decide between them, and a workload couldn't
tell which piece of hardware it had opened.

**Paths aren't checked for existence when the inventory is stored.** The secret
is minted on the hub and may be used by a container executor on another machine,
so the broker can't check the right host. It checks only the form, which doesn't
depend on the host; see [What the inventory refuses](#what-the-inventory-refuses).

Each grant then opens a different part of it to a different project:

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

**`--devices` is required, and it matches names, not paths.** `serial0` is exact,
`gpu*` is a glob, and `*` alone allows every device in the inventory. Matching is
case-sensitive, because an operator chooses these names: case-insensitive
matching would make a grant for `gpu0` also open `GPU0`, which could be a
different piece of hardware. One grant may open at most 16 devices, the same
limit as a sandbox spec, so a grant can't deliver more than the dispatch path
accepts.

Omitting it is refused at creation, not at delivery:

```console
$ cloop secret grant bench-hw --to project:/srv/projects/firmware --ttl 8h
Error: secretbroker: invalid constraint: a host_device grant needs a device
allowlist (--devices serial0, or --devices '*' for every device in the inventory)
```

So is an allowlist that matches nothing. Otherwise the harness would start and
only find the problem as an `ENOENT` on a path it was told to expect.

### What the sandbox actually gets

Each granted device appears at its target path (the same path as on the host,
unless the inventory remapped it), with the access mode the grant resolved to:

```
devices: /dev/ttyACM0  ->  /dev/ttyACM0   r
         /dev/ttyUSB0  ->  /dev/ttyUSB0   rw
env:     CLOOP_HOST_DEVICES=analyser,serial0
```

`CLOOP_HOST_DEVICES` lists the names, never the host paths. The name is what the
project was granted and what its code refers to, and a workload that needs a
path opens the device it was given. Host paths in the environment would reveal
the host's hardware layout to every process in the sandbox, for no benefit.

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

The delivered list is sorted by name, because it goes into an audit row and a
`Spec` that `pkg/executorstore` stores, and neither should vary between identical
runs.

A project selects from this by name in its own repository:
`capabilities.devices: [serial0]`, or leave the key out to take everything the
project holds. Naming a device the project has no grant for is an error. That is
stricter than `env:`, where a name the project doesn't hold forwards nothing,
because a missing variable degrades a run but a missing device node makes a
firmware build meaningless. See the [sandbox spec reference](../reference/sandbox.md).

### Narrowing is the only direction

`writable` widens access, so, as for `local_repo`, it is a bool that defaults to
the safe value. A constraint may take access away, but never add it:

- a grant without `--writable` narrows every device it opens to `r`, whatever
  the inventory recorded;
- a grant with `--writable` can't upgrade an entry the inventory recorded as
  `:r`. The analyser above stays read-only under the `--writable` grant that
  opened it.

This lets one inventory serve several projects. An operator who decides that
nothing may ever reprogram the analyser writes `:r` once, in the inventory, and
no grant, spec or flag downstream can undo it.

### The access mode is not a boundary on every host

Read this before you rely on a read-only device grant.

The mode becomes the third field of the runtime's `--device src:dst:perms`, which
programs the container's device cgroup. On cgroup v1 that is the devices
controller. On cgroup v2 it is an eBPF program attached to the container's
cgroup, and whether it is attached at all depends on the kernel, the runtime
build and the cgroup delegation, none of which cloop can query. On a host where
it isn't attached, a device granted `r` is readable and writable, because the
node inside the sandbox has the host node's file mode, and `/dev/zero` is `0666`
nearly everywhere.

So the mode is an extra layer of protection, not a guarantee. The container
driver's preflight (phase one of `cloop executor test`) says so:

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

The warning always appears, because it is a statement, not a test. Finding out
whether the cgroup rule is enforced would mean starting a container, granting it
a device read-only and trying to write, which would add a container run and an
image dependency to a command an operator may run on a node with nothing pulled
yet.

**The node's own ownership and mode work on every host.** The sandbox runs as the
UID that owns the project directory, so a sandbox whose UID isn't in the group
can't open a device at `crw-rw---- root:dialout`, whatever the cgroup does. An
operator who needs read-only access enforced sets it there, with `chown`/`chmod`
and a udev rule so it survives a re-plug. The full recipe is in
[critical hosts as cloop executors](enterprise-hosts.md#what-the-access-mode-does-and-does-not-enforce).

cloop still sets the mode, because on hosts where the cgroup rule is enforced it
works as intended, and withholding `mknod` by default costs nothing.

### Not every executor can receive it

`local_repo` reaches a workload in three ways, depending on the driver. This kind
reaches it on one driver only:

| Executor | What happens | `SupportsDevices` |
| --- | --- | --- |
| `container` (runc; not under Kata or gVisor, which serve `/dev` from their own kernel) | each device is exposed at its target path with the granted mode | ✅ (❌ under Kata or gVisor) |
| `kubernetes` | **refused**: Kubernetes doesn't take device paths | ❌ |
| `remote` | **refused**: the grant names a path on the hub's host, and the agent has no sandbox to put a device into | ❌ |
| `localprocess` | not exposed and **not enforced**; a warning is logged | ❌ |

On `kubernetes`, a device plugin owns the node and gives a container whichever
unit it has free, in response to an extended resource request. A grant that
names a path doesn't fit that model, and mounting `/dev/nvidia0` as a hostPath
on whatever node the scheduler picked would expose an unrelated piece of that
node's hardware, which is worse than refusing. (`HostDevice` has a
`kubernetes_resource` field for the resource request this driver would need, but
nothing uses it yet.)

On `remote`, two things stand in the way, and only one of them is a missing
feature. A grant naming `/dev/ttyUSB0` on the hub says nothing about
`/dev/ttyUSB0` on a machine in another building. And the agent runs each
workload with `localprocess`, as a plain process in its own namespaces, so it
has no sandbox to put a device into. To pass hardware into a confined sandbox,
run the container executor on the machine that has the hardware.

`localprocess` only gets a warning, because the workload is a plain process in
the hub's own namespaces and can already open every device node the hub user
can. There is nothing to expose and nothing that could be withheld. So that the
dashboard doesn't suggest a scoped device grant on a workload that has all of
`/dev`, a line goes to the hub's stderr naming the grant and telling you to bind
a container executor to enforce it.

The refusals happen at placement, and name both facts:

```
executor: invalid spec: executor k8s-prod (kubernetes) cannot expose host devices
inside a sandbox, but this project holds a host_device grant for serial0. A device
grant names hardware on one machine, so bind the project to a container or Kata
executor running on the host that has it
```

It is an error, not a warning, for the same reason as `local_repo`'s: this is the
moment when "I granted this bench's hardware to that project" and "I bound that
project to a cluster" turn out to be incompatible, and the person who needs to
know is the one who just pressed Run. When a spec with devices is placed or
failed over across a fleet, the same requirement is called `devices`; see
[Placement](../architecture/executors.md#placement).

### Revocation lapses when the workload exits

This is the same limitation as for `local_repo`, and harder to work around. A
device already in a running sandbox's cgroup and mount namespace can't be taken
back from outside, as a bind mount can't. Revoking the grant removes it
from the run's lease at once and it is never issued again, so no new run gets
the hardware, but the run that already has it keeps it until it exits. The
devices are recorded on the lease for the audit trail, not for revocation,
because the hub can't take them back.

To close that window, revoke the grant and then stop the workload, with the
dashboard's Stop button or by revoking the run's lease with `action=kill`.
[Cordoning the executor](../architecture/executors.md#placement) leaves running
work alone. There is no top-level `cloop stop`:

```console
$ cloop secret revoke grant_7f3a1c
✓ revoked grant grant_7f3a1c (bench-gpu)
  hub member hub-5d1e0c on build-01: taken back from 1 lease(s) — revoked
```

"Taken back" covers what the lease delivered as files and variables. The device
node itself stays in the sandbox until the run is stopped.

**Rely on grant TTLs here, not revocation.** Eight hours for a bench session is
better than a week, because the grant's expiry is what ends the session instead
of leaving the project with standing access to the machine's hardware.

### What the inventory refuses

The broker can't know which host will use a device path, so it checks what is
true on any host. A path must be absolute, canonical (`/dev/../etc` is refused
instead of cleaned, because the two differ only when someone wrote something
they didn't mean), at most 256 characters, and free of backslashes, NULs and
newlines.

Beyond that, two kinds of path are always refused.

**Devices that would make the sandbox pointless.** `/dev/mem`, `/dev/kmem`,
`/dev/kcore`, `/dev/port`, `/dev/msr` and `/dev/cpu` exist to give direct access
to the machine, and whole host disks (`/dev/sda`, `/dev/nvme0n1`, `/dev/vda`)
hand over every filesystem on them:

```
secretbroker: malformed secret payload: host_device line 1: device "ram" source
path "/dev/mem" maps all of physical memory, including kernel text, so granting it
would waive every isolation guarantee the sandbox provides
```

A denylist on top of an allowlist is usually a bad sign. It is needed here
because the allowlist is "any absolute path under `/dev` that an operator
typed", and an operator who types `/dev/mem` has made a mistake no later layer
can catch: it would undo every form of confinement cloop provides. Grant a
partition instead, or grant a directory as a `local_repo`.

**Anything outside `/dev`.** The field takes a device node. A regular file here
would be a host bind mount under a device's name, bypassing the `local_repo`
grant that exists for that purpose, and its symlink containment:

```
secretbroker: malformed secret payload: host_device line 1: device "src" source
path "/srv/git" is not under /dev; grant a host file or directory as a local_repo
instead
```

Both checks run twice, once at each end. The broker's check is there to give a
helpful error: over the API and the dashboard, the inventory is parsed as it is
stored, so the error appears in the dialog in front of the person who typed the
path. `pkg/executor`'s check is the one that enforces the rule. It runs again
immediately before a driver builds a runtime flag, because by then the `Spec` has been
stored and loaded again, and this field puts a host path unchanged into the argv
of a root-privileged runtime CLI.

[Critical hosts as cloop executors](enterprise-hosts.md) covers the whole host
setup: the inventory, the udev rules, gVisor, the egress filter, and how they
fit together on one bench machine.

---

## Host network interfaces

`host_device` can't carry a network interface. A netdev isn't a node under
`/dev`, so there is nothing to bind and no cgroup rule to write, and neither
runtime has a flag for it. `host_interface` can: it moves an interface out of
the executor's network namespace and into the sandbox's, so the workload sits
directly on the network segment instead of reaching it through the host. That
makes ARP, DHCP and raw Ethernet work, which is usually why a machine is wired
to a board in the first place.

It is the widest grant the broker issues, and the only one that takes something
away from the executor: an interface lives in one namespace at a time, so the
host can't use it while the run holds it.

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

Each line is `name=ifname` plus optional comma-separated attributes: `target=`,
`address=` (a CIDR), `gateway=` (needs `address=`) and `mtu=`. Attributes are
separated by commas, not colons, because addresses such as `fd00::10/64` contain
colons. `--interfaces` is required for the same reason as `--devices`: a grant
with no allowlist would open every segment in the inventory.

`.cloop/sandbox.yaml` then selects from what the project holds, and can only
shorten the list:

```yaml
capabilities:
  network: bench-egress
  interfaces: [dut]
```

Before you mint one, note what is refused:

| Refused | Why |
| --- | --- |
| `lo`, `docker0`, `podman0`, `cni-podman0`, `virbr0`, `br-*` | moving one would disconnect the host or every container on it. A Docker per-network bridge is what the sandbox's veth peer attaches to, not something to move |
| the interface carrying the host's default route | checked on the executor when attaching, where the routing table can be read. On a remote bench, moving it would make the machine unreachable |
| a Kata or gVisor executor | the move would succeed but the workload would still see nothing, because both build their view of the network when the sandbox starts. Refused at placement instead of attempted |

Revocation has the same limit as for `host_device`: an interface already inside a
running sandbox's network namespace can't be reached from outside, so a revoked
grant lapses when the workload exits. Stopping the run cuts it off immediately.
Stopping gracefully also returns a veth pair to the host intact; otherwise the
kernel deletes virtual interfaces along with the namespace instead of handing
them back.

[Network interfaces: L2 passthrough](enterprise-hosts.md#network-interfaces-l2-passthrough)
has the full bench recipe: the bridge, the veth pair, the runtime constraints and
the start-up window.

---

## Egress leases

A sandbox runs with `--network=none`, or on an `--internal` bridge with no route
off the host. `cloop egress` gives it a way out: the hub hosts an authenticated
forward proxy (`executors.egress`; see
[the configuration reference](../reference/configuration.md#scoped-network-egress)),
and every run whose project holds a grant gets a session on it. `egress_proxy` is
one of the grantable resource types.

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
| `--hosts` | — | `api.example.com`, `*.example.com` (subdomains only, not the apex), or `'*'`. No implicit wildcard |
| `--cidrs` | — | destination IP prefixes; the only way to reach a private range |
| `--ports` | `80,443` | destination port allowlist |
| `--methods` | `*` | plain-HTTP methods only, since CONNECT tunnels are opaque |
| `--max-up` / `--max-down` | unlimited | per-session byte quota (`100m`, `2g`) |
| `--session-ttl` | `15m` | one redeemed proxy session; hard ceiling 4 h |
| `--ttl` | `24h` | the grant itself |

At least one of `--hosts` or `--cidrs` is required.

**Private ranges are blocked unless you name them.** Loopback, RFC1918 and
link-local addresses are refused even under `--hosts '*'`. Reaching them takes
an explicit CIDR, which adds a step to the SSRF path:

```console
$ cloop egress grant --to label:region=eu --cidrs '10.20.0.0/16' --ports 5432 --session-ttl 30m
```

A cloud metadata service (`169.254.169.254`, AWS's IPv6 `fd00:ec2::254`, Alibaba
Cloud's `100.100.100.200`, and the others in `pkg/cloudmeta`) is stricter still:
reaching one takes a CIDR that names its own address. A `--cidrs` that only
contains one (say `169.254.0.0/16`) is refused, and the error names the service.

**What the proxy enforces** before the first byte leaves: host, port and method;
resolving the destination name once, checking every resolved address against
the policy, and dialling the checked address (so a DNS answer that changes
between check and dial can't redirect the connection); private-range blocking;
byte quotas, cut off mid-stream; and the session TTL, applied to open tunnels as
well as new ones.

It doesn't enforce anything inside a CONNECT tunnel. cloop holds no key for the
origin, so it counts bytes, not content.

**What a run gets.** At dispatch the hub redeems one proxy session for the run,
under the newest active grant for its project (a feature uses its parent
project's), or under the grant its `.cloop/sandbox.yaml` names in
`capabilities.network`. The sandbox receives `HTTPS_PROXY`/`HTTP_PROXY` (and the
lowercase spellings) carrying the session's credential, `NO_PROXY` (loopback and
the hub's own git proxy and Kubernetes monitor), and `CLOOP_EGRESS_SESSION`,
`CLOOP_EGRESS_ALLOW` and `CLOOP_EGRESS_GRANT_ID`. The session token is
single-use and only its SHA-256 is stored, so a dump of the control plane
doesn't contain a usable proxy credential. The variables carrying it are marked
sensitive, so they are scrubbed from the run's output and never written to the
journal, the audit trail or the dispatch record.

**How long it lasts.** One session period (`--session-ttl`, capped by
`executors.egress.max_session_minutes`), renewed while the run lives but never
past the grant's own expiry, and closed when the run ends or is stopped, or the
hub shuts down. Each renewal is an `egress.renew` audit row.

**When it gets none.** The project's event journal says why in an `egress` row:
the grant was revoked or expired; the hub hosts no proxy, or its proxy didn't
bind; the run has no network to reach it over; or the project's executor has no
route to it (a container sandbox and a loopback-bound proxy, or a device and an
advertised address it can't reach). If the project's `.cloop/sandbox.yaml` names
the grant, the run is refused instead, with a `409` and the fix.

**Harness traffic counts.** A harness that honours `HTTPS_PROXY` sends all of its
HTTP through the proxy, including its own model API calls. In a sandbox whose
only way out is the proxy, name the model API's host in the grant
(`--hosts api.anthropic.com`), or the harness can't reach its model.

### Testing a grant without starting a sandbox

```console
$ cloop egress test https://api.github.com/rate_limit
$ cloop egress test https://internal.example.com --to label:region=eu --timeout 10s
```

This redeems a real session and sends the request through the same code path a
container uses, so a pass means the policy really allows it.

`--to executor:edge-01` tests as that executor, with the labels the hub records
for it, which is how a run on it is checked. `--to label:region=eu` tests as an
imaginary executor with exactly those labels, and says so. Whether any real
executor has them depends on the hub's records: `cloop egress grant` prints
which executors do when it issues a label grant, and the Secrets panel lists
them under the grant.

---

## Inspecting, debugging, revoking

```console
$ cloop secret grants
GRANT                            SECRET             KIND          SUBJECT                  EXPIRES    CONSTRAINTS
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────
grant_8ce0add1fec2ed4fa00c3a23   deploy-pat         github_pat    project:/srv/app         24h0m0s    repos=myorg/* perms=contents:read

1 grant(s)
```

Filter it with `--subject`, `--secret` and `--all` (which includes expired and
revoked grants).

**"Why isn't my token arriving?"** Dry-run the lease. It shows what an executor
would receive (allowlists and file names, never payloads):

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

### Revoking a grant

```console
$ cloop secret revoke grant_8ce0add1fec2ed4fa00c3a23
✓ revoked grant grant_8ce0add1fec2ed4fa00c3a23 (deploy-pat)
  hub member hub-5d1e0c on build-01: taken back from 1 lease(s) — revoked
    container: revoked — 3 file(s) removed
$ cloop egress revoke egress_b9c92d36cdec6a598e1bd797
$ cloop egress list --all
```

Both take access back from a run that already has it, in different ways, and the
difference matters during an incident:

- **Secret grants** are taken back from every workload holding them at once, not
  at the next renewal. Each hub member holding a lease that carries the grant
  wipes the grant's files from its own copy, sends every executor holding the
  lease a revocation limited to that grant, closes the git proxy and Kubernetes
  monitor sessions the grant fed, and destroys the GitHub App tokens minted for
  it. A lease that carries other grants keeps them, and the run keeps working
  with them. The Secrets panel's **Revoke** does this from the hub, and first
  tells you how many running workloads hold the grant and which hold it in their
  environment. `cloop secret revoke` runs outside the hub, so it announces the
  revocation on the hub bus and waits up to `--wait` (default `60s`) for every
  running member to report what it took back. It names any member that didn't
  answer, and says so when no hub is running at all. Whatever the announcement
  doesn't reach (a hub started with `ui.cluster.exclusive` reads no bus), the
  lease janitor finds within a minute.
- **Egress grants** are cut off immediately: every live session under the grant
  is closed at the proxy, even mid-tunnel. Revoked in the dashboard of the hub
  holding the session, it closes at once. Revoked with the CLI or on another hub
  member, the hub holding it notices within a minute, because it re-reads the
  grant every minute of the run. The project's journal records the close and how
  many open tunnels it cut.

A grant revocation can't take back what a lease scrub can't
([below](#what-a-scrub-actually-reaches)): a variable already in a running
process's environment. A host process or a device's task keeps its copy until
it exits. A container or Kubernetes Pod holding the grant in its environment is
removed instead, because its runtime keeps a copy that only removing the
workload destroys. The outcome says the workload was *terminated*, and the
panel's confirmation names those workloads before you confirm. A repository
bound in by `local_repo`, a `host_device` and a `host_interface` stay in the
sandbox until it exits (their sections above say why). Of several kubeconfig
grants merged into one document, revoking a monitored one closes its session and
leaves the document, while revoking one whose cluster credential is in the
document takes the whole document
([several kubeconfig grants](#several-kubeconfig-grants-on-one-project)). If
the credential itself is compromised, also rotate it at the source, and revoke
the run's lease with `action=kill`.

**Editing isn't always revoking.** Changing a project's repository assignment in
the panel, or granting a Claude credential again for longer, creates a new grant
and retires the old one. If the new grant keeps the credential and allows
everything the old one did (more repositories, read access raised to write, a
branch list removed), the old grant is retired as *superseded*, and its row
names its successor. Nothing is taken back from a running task: its lease now
depends on the new grant, is extended while that grant lasts, and ends with it.
An edit that narrows anything (a repository or permission removed, a branch
dropped, a branch list added) or switches the credential revokes the old grant.
A running task loses the old access at once, as it would with **Revoke**, and
its next lease carries the new terms. Only literal coverage counts, so rewriting
`acme/app` as `acme/*` also counts as narrowing. A Claude credential granted
again supersedes the old grant even with a new secret, and the running task
keeps the old token until it ends, or until you delete the old secret, which
takes it back.

Revoking an already-revoked grant succeeds and takes nothing back a second time.
Every grant, revoke and lease decision is audited with actor, subject,
constraints and reason, never with material
([`TestSecretBrokerDecisionsNeverCarryMaterial`](../security/model.md#the-guarantee--test-table)).

---

## Revoking a lease from a running task

Revoking a *grant* takes that grant back from every lease that carries it.
Revoking a *lease* takes back everything one running task holds, whichever grant
it came from:

```console
$ curl -X POST https://cloop.example.com/api/leases/lease_8ce0add1/revoke \
    -H "Authorization: Bearer $CLOOP_TOKEN" \
    -d '{"action":"scrub","reason":"PAT rotated"}'
```

or press **Revoke** in the Secrets panel's *Live leases* table. The hub wipes its
own copy and sends a `revoke` frame to every executor holding the lease, and
each one scrubs the material and acknowledges.

### What a scrub actually reaches

Read this before an incident, not during one. A scrub does three things with
three different strengths, and the API reports which one you got instead of
a plain "revoked":

| Material | Effect of a scrub | Strength |
| --- | --- | --- |
| Credential **files** (kubeconfig, the git credential helper's token file, registry auth) | zeroed and unlinked on the device | **Strong**: the next read fails |
| **Egress** allowlist entries | dropped at the proxy and on the agent | **Strong**: the next connection is refused |
| Environment **variables** | dropped from the agent's memory, so they are never re-injected on a restart, resume, or failover | **Weak**: the running process already has its own copy |

The weak case can't be fixed. The kernel hands a process its environment at
`exec` time, and nothing outside the process can reach into that memory
afterwards. That is why cloop delivers GitHub tokens through a credential helper
that reads a token file, instead of exporting a bare `GITHUB_TOKEN` (see
[What the sandbox actually gets](#what-the-sandbox-actually-gets)): it puts the
PAT in the row that can actually be revoked.

If the credential itself is compromised, not only granted too widely, use
`{"action":"kill"}`. The agent scrubs and then terminates every task holding the
lease: `SIGTERM`, then `SIGKILL` five seconds later, so a harness that traps the
signal can't outlive the revocation.

### When the agent is unreachable

A revocation reaches a device only if the device is reachable. The response and
the panel report one of four states, and only the first means the material is
gone:

| State | Meaning |
| --- | --- |
| `revoked` | every holder acknowledged; the scrub is done |
| `revoke_pending` | the frame is in flight |
| `unreachable` | at least one holder is offline, and **the credential is still on that machine**. The revocation is queued and replayed as soon as it reconnects |
| `failed` | a holder answered with an error; read the per-executor detail |

The overall state is the worst holder's. If three devices out of four have
scrubbed, the revocation isn't done.

If you see `unreachable` and the credential is compromised, revoke it at the
source (rotate the PAT at GitHub, rotate the kubeconfig's credentials), because
that is the only action that doesn't depend on a machine you can't reach.

### When the hub member holding the lease is gone

On a [hub cluster](../architecture/hub-cluster.md), a lease is held by the member
that dispatched (or adopted) its run. If that member has died, no live process
holds the lease, and a revoke can't reach the workload yet. It is recorded
anyway, and answered with `202` instead of `404`:

```json
{"ok": true, "recorded": true, "state": "revoke_pending",
 "pending": [{"executor_id": "container", "state": "revoke_pending",
   "error": "recorded; takes effect when hub member hub_7c1… 's run is reached: …"}]}
```

A revoke made in the seconds after a member died, before any member has decided
it is dead, can't ask that member and gets the same answer. The member is listed
under `pending` as `hub member <id>`, "could not be asked", instead of as an
`unreachable` holder. The record applies whether the member stopped or is only
cut off: if it is still running, its own lease janitor takes the credential
back, and no hub process extends the lease in the meantime.

From then on, no hub process may take the lease over or keep it alive. The
member that adopts the run (the leader for a container, Pod or host process, and
the member holding the agent's socket for an agent's run) takes the credential
back from the workload instead of restoring the lease, and restores none of the
git proxy or Kubernetes monitor sessions it fed. A revoke made after a member is
judged dead makes the leader adopt the run at once, or reach the container or
Pod through its executor if the run can't be adopted, so it is usually enforced
before the request returns. A host process the dead member started keeps
running, but its credential directory is wiped as soon as a member notices the
death. Until a pending revocation is enforced, the workload keeps what it was
given, so revoke at the source if that matters.

`not revocable` in the panel means a holder can't act on a `revoke` frame.
Usually that is an agent older than protocol v2, but an offline device or a
driver that can't revoke shows it too; the chip's tooltip says which holder and
why. The hub refuses to place new revocable material on such an agent, so the
old-agent case only appears for a device downgraded after a placement. Fix it by
upgrading the device as the tooltip says. How depends on whether the hub runs a
published release (press Upgrade) or an unreleased build (put the device on the
[edge channel](edge-channel.md) and press Upgrade to install the hub's own
build, signed by CI, or install a binary built from the hub's commit with
`sudo ./cloop executor agent install --upgrade --insecure-skip-verify` on the
device). `install --upgrade` replaces the binary and restarts the service,
leaving the unit file and the enrollment credential untouched. It is
idempotent, so it is safe to run again. See
[Moving a device forward](../architecture/executors.md#moving-a-device-forward-which-remedy-works),
and the build-version reporting that tells you which devices need it.

### The four triggers

Revocation can start in four ways, all using the same path:

1. **Explicit**: the Secrets panel or `POST /api/leases/{id}/revoke`.
2. **TTL expiry**: a janitor runs once a minute and scrubs every lease whose TTL
   has lapsed from every holder: a device, and the hub's own host-process,
   container and Kubernetes drivers. A container's staged files are unlinked and
   a Pod's lease Secret loses its keys. Before the janitor existed, only the
   caller that minted a lease checked `Lease.Expired`, so a fifteen-minute
   credential handed to a three-hour task stayed there for three hours.
3. **Cordon and drain**: taking a device out of rotation scrubs everything it
   holds. This works from the dashboard or with `cloop executor cordon` and
   `drain`, which tell the running hubs over the hub bus and print which member
   held the device's connection and which leases are still pending. It scrubs
   instead of killing, because draining waits for running work to finish, and
   killing that work would contradict the operation you asked for. When the hub
   member holding the device's connection can't be asked, or no hub is running,
   every lease issued to the device is recorded as revoked: the member you
   cordoned it on revokes it from there, and the next hub to start enforces the
   rest. Cordoning an executor on the hub itself (its container runtime, a
   cluster, the host) takes nothing back.
4. **Grant revocation**: [revoking a grant](#revoking-a-grant), or deleting the
   secret it points at, scrubs that grant from every lease that carries it and
   leaves the lease's other grants in place.

Each step is audited as `lease.revoke_sent`, then `lease.revoke_acked` or
`lease.revoke_failed`, with the lease and executor IDs and how long the
acknowledgement took. A revocation is sent first and takes effect later
(possibly minutes later, when an offline device reconnects), so each step has
its own row. A single row would claim the credential was withdrawn at a time
when it still worked.

---

## The Secrets panel

Everything above is also available in the dashboard's global **Secrets** tab,
for operators who don't have a shell on the hub. It has three tables, matching
the three concepts in [The model](#the-model):

- **Stored secrets**: name, kind, fingerprint, and how many grants point at
  each. **+ Secret** stores one.
- **Grants**: grants from both brokers in one list, with each row's full
  allowlist and a live countdown. **+ Grant** opens a wizard for the chosen
  kind: repository allowlist and permission subset for a PAT, context and
  namespace for a kubeconfig, host allowlist with byte quotas for egress, and
  registry or env-key allowlist for the rest. The wizard offers only secrets of
  the chosen kind, and there is no "allow everything" default: an empty
  allowlist is rejected by the same `Constraints.ValidateFor` the CLI uses.
  **Revoke** first says how many running workloads hold the grant and which hold
  it in their environment (containers and Pods among those will be removed),
  then takes it back from all of them and lists what each holder did.
- **Live leases**: the leases outstanding right now, with their executor,
  project, credentials and time left. **Revoke** wipes that workload's
  credential directory immediately instead of waiting for the lease to end.

Each row links to the [Audit panel](../security/model.md), filtered to that
secret or grant, so you can see who granted it and when with one click.

### What it will not show you

No endpoint behind this panel returns secret material or a decrypted lease
token: not on a read, not in the response to a create, and not in an error
message. Each row shows a **fingerprint** instead: `sha256:` of the sealed
record, truncated to 16 hex characters.

A digest of the plaintext would let you compare two secrets, but it would also
let anyone who can read the endpoint test guesses offline, which would expose
the low-entropy values the store also holds (a registry password, an env value).
So the fingerprint identifies the stored record, not the value: storing the
same credential twice gives two different fingerprints. Use it to confirm that a
rotation changed something, not to check whether two secrets match.

`TestSecretsAPIRoutesNeverDiscloseMaterial` stores known plaintext of every kind
and calls every route (reads, writes, and the error paths that hold a credential
while they build their message), and checks that the known value appears in
none of the responses, in any encoding.

### Who can see it

Below **maintainer**, the tab is hidden and every route behind it is refused:

| Route | Permission |
| --- | --- |
| `GET`/`POST` `/api/secrets`, `/api/grants`, `GET /api/leases` | `secret.grant` |
| `DELETE /api/secrets/{id}`, `DELETE /api/grants/{id}`, `POST /api/leases/{id}/revoke` | `secret.revoke` |

`GET /api/grants/{id}/holders`, the preview the revoke confirmation uses,
answers for any grant the caller can see in `GET /api/grants`. The owner of a
personal grant sees how many of their workloads hold it and how. Which executor
and project each one is on is shown only to a caller with `secret.grant`, who
can read the fleet's leases anyway.

Reading needs `secret.grant`, not `project.read`, because a list of which
credentials exist, which executor holds them and what each may reach is useful
to an attacker, and a role that can't grant access has no reason to see it.
Being able to use a credential (which an operator can, by starting a run) is
different from being able to list the fleet's credentials.

Every create and revoke is recorded in the audit trail under the operator's OIDC
identity, not under `ui`. A lease revoked from the panel writes a second row
naming the person who pressed the button, because the broker's own release event
only names the executor.

### Approvals: the inbox and notifications

A grant request waits for someone who may decide it, and an API token minted
with no role policy in force waits for an administrator once a policy is
enforced. A request lapses after 72 hours if nobody decides it, so the hub tells
the people who can act:

- **The header badge.** Next to the scope hint, every dashboard shows how many
  items are waiting for the signed-in user: requests they may decide and tokens
  they may approve. Each user's count comes from `GET /api/approvals/count`,
  fetched again whenever the hub broadcasts that a request was filed, decided,
  withdrawn or lapsed, or that a token started waiting, was approved or was
  revoked. The broadcast carries only an event name and an id, never the row. A
  change made on the hub's host with `cloop hub grant`, which no dashboard
  handler sees, is broadcast by the notifier on its next pass, within 30
  seconds. The badge also refreshes when the soonest deadline passes.
- **The inbox.** The badge opens a list, soonest deadline first, with each
  request's requester, credential, subject, allowlist and justification, and
  each token's roles and minter. **Approve…**, **Deny…** and **Review…** open the
  Secrets tab's decision dialogs, which load the item again. Below the list, the
  signed-in user's own requests show how they ended (approved and by whom,
  denied with the approver's reason, or lapsed), and an open dashboard says so
  when one of them is decided.
- **The terminal.** `cloop remote approvals list|approve|deny` for an approver
  signed in with `cloop login`, and `cloop remote grants list` for the
  requester.

Someone's inbox holds exactly what the decision routes would let them decide.
For requests, that is a pending request filed by somebody else, for a subject on
which they hold `secret.grant` hub-wide (as approving has always required), and,
for a request aimed at every project or executor or at a label selector, only if
they are an administrator. For tokens, it is only under an enforced role policy,
and only for an administrator who holds every role the token carries. A
maintainer of one project, a viewer and the requester see nothing to decide. A
runtime deny on a project removes that project's requests from the denied
approver's inbox, and the decision route refuses them in the same way.

**Notifications** send the same news to a channel: Slack, a Microsoft Teams
Workflows trigger (an Adaptive Card), Discord, or any receiver of a JSON POST.
An administrator configures them under
[`notifications`](../reference/configuration.md#approval-notifications-notifications)
or in Settings → Notifications. The cluster leader posts once per cluster when a
request is filed, 12 hours before it lapses, when it is approved, denied,
withdrawn or lapses, and when a token starts waiting. A message carries
identities, the credential's name and kind, the subject, the deadline and a link
to the inbox. It never carries credential material or the justification, and
every string goes through the credential-pattern scrubber first. The webhook URL
is the channel's credential: it is only posted to over https, never returned by
the dashboard's API, and the sender refuses a redirect, a cloud metadata
address, and a private or loopback receiver its configuration doesn't name.
`TestApprovalsInboxListsOnlyWhatTheCallerMayDecide` tests who sees what,
`TestApprovalRemindersGoOutOncePerCluster` the once-per-cluster reminder,
`TestClientRefusesCloudMetadataEvenWhenAllowed` and
`TestClientNeverFollowsARedirect` the sender, and
`TestRenderedMessagesCarryNoSecretMaterial` the messages.

### When the owner of a personal secret leaves

Offboarding destroys a departed person's personal secrets and revokes every
grant of them, including grants to projects other people own. If your project
was granted a colleague's credential, its next run is refused it, with an error
naming it (`github_pat "alice-pat", a personal credential of
alice@example.com, was destroyed … when its owner was offboarded`), in the audit
trail and as a `credential_refused` event on the project's Activity tab. Grant
the project a credential owned by someone still on the hub: a shared secret from
a maintainer, or one of your own. Under a legal hold the secret is kept, but its
grants are still revoked (the refusal then says the credential was *withdrawn*
when its owner was offboarded), and only its departed owner could grant it
again. See the [runbook](../operations/runbook.md#somebody-leaves).

---

## Choosing TTLs

| | Default | Ceiling | Guidance |
| --- | --- | --- | --- |
| Secret grant `--ttl` | 24 h | — | set it to the length of the work; a one-off migration needs `--ttl 2h` |
| Lease | 15 min | 15 min | not configurable per grant; swept off every holder within a minute of lapsing |
| Egress grant `--ttl` | 24 h | — | as above |
| Egress `--session-ttl` | 15 min | 4 h | longer sessions mean revocation takes effect later |
| Enrollment token `--ttl` | 15 min | 24 h | it is a bearer secret in transit, so keep it short |

The lease TTL is the number that matters when nobody is watching: a lapsed lease
is swept from its executor within a minute of expiry, so the TTL plus the
janitor interval limits how long unattended material stays valid. When someone
is watching, revoke the lease or the grant directly, which takes effect in one
round trip instead of at the end of the TTL. Neither limit applies to an
unreachable agent; see
[When the agent is unreachable](#when-the-agent-is-unreachable).

Materials are written into a 0700 tmpfs directory (`/dev/shm` where available),
zeroed and removed when the workload exits.

---

## See also

- [Security model](../security/model.md): what each guarantee covers
- [Threat model](../security/threat-model.md): SSRF, exfiltration, revocation lag
- [Executor architecture](../architecture/executors.md): where a lease is applied
- [Operator runbook](../operations/runbook.md#key-rotation): rotating the sealing key online with `cloop hub key rotate`
