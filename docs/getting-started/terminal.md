# Working from a terminal

Some work on a hub with single sign-on is easier from a terminal than from a
browser: opening a shell in a running task's sandbox, following a run's output
next to your editor, or adding a task without switching windows. `cloop login`
gives your terminal its own session, which you approve in the browser you are
already signed in with. No administrator has to create a token for you, and
nothing long-lived is created: the terminal gets a session like your browser's,
with the same rules.

- [Signing in](#signing-in)
- [What the approval page is telling you](#what-the-approval-page-is-telling-you)
- [What the terminal gets](#what-the-terminal-gets)
- [Using it](#using-it)
- [From a checkout to a running project](#from-a-checkout-to-a-running-project)
- [Sharing a Kubernetes cluster](#sharing-a-kubernetes-cluster)
- [Signing out](#signing-out)
- [Where the session is kept](#where-the-session-is-kept)
- [When it does not work](#when-it-does-not-work)
- [For the hub's operator](#for-the-hubs-operator)

---

## Signing in

```console
$ cloop login https://cloop.example.com
To sign this terminal in to https://cloop.example.com, open

    https://cloop.example.com/device

and enter the code

    WDJBM-JHTNB

(or open https://cloop.example.com/device?code=WDJBM-JHTNB)

Approve it only if the page shows this code. It expires in 10m0s.
Waiting for approval…
```

Open the link in a browser signed in to the hub. On a desktop, `cloop login`
opens it for you (`--no-browser` turns that off). If the browser isn't signed
in, the hub sends it to your identity provider first and then back. The page
shows the code and where the request came from. Check that the code matches
your terminal, then press **Approve**. The terminal prints:

```console
Signed in to https://cloop.example.com as alice@example.com.
The session lasts until 2026-10-12 09:14 UTC, or until it goes unused for 8h0m0s.
```

Approving sends the browser through your identity provider once more. Usually
the provider recognises you and sends it straight back. But if you last signed
in there more than two hours ago (`ui.oidc.device_approval_max_age_minutes`),
it asks you to sign in again first. Approving a code creates a credential, so
it needs a recent sign-in, like a code forge's "sudo mode". The hub uses the
sign-in time the provider reports (`auth_time`), so signing out of the
dashboard and back in without typing a password doesn't reset it. With a
provider that reports none, the hub asks for a fresh sign-in whenever your
dashboard session is that old.

The same two hours then apply to the terminal's privileged actions, the hub's
sudo mode (`ui.oidc.sudo_max_age_minutes`): approving a grant request, creating
a token, opening a sandbox terminal with `cloop task attach`, and the other
actions the dashboard asks you to confirm. They count from the sign-in behind
the approval, which is the approval itself if the provider asked you to sign in
(it always does when your dashboard sign-in is older than the window). After
that, the hub refuses these actions and the terminal says so:

```console
$ cloop remote approvals approve gr_3f…
Error: this action needs a recent sign-in, and this terminal's session was approved more than 2 hours ago: run `cloop login https://cloop.example.com` again, then retry
```

To fix it, run `cloop login` again. The `Privileged actions:` line of
`cloop whoami` shows how much longer the session can take these actions.

| Flag | Does |
| --- | --- |
| `--ca-file <pem>` | Trust this PEM bundle for the hub's certificate, for a hub behind an internal CA. It is stored with the session, so later commands use it too |
| `--no-browser` | Print the link without opening a browser |
| `--default` | Make this hub the default for commands that don't name one. The first hub you sign in to is the default anyway |
| `--hostname <name>` | What the approval page calls this machine (default: its host name) |

While it waits, the terminal checks with the hub every five seconds. Press
`Ctrl-C` to give up. A code that nobody approves expires after ten minutes.

## What the approval page is telling you

**Only approve a code you started yourself.** Approving signs in *whoever is
running that terminal* as you, with your permissions. The known attack on this
kind of sign-in is a code someone else started and sent to you with a plausible
story, such as "please approve this so the deploy can continue". The protocol
can't tell that code apart from your own, so the page shows you what you need
to notice it:

- **The code.** It must be the one your terminal printed.
- **Requested from**: the address the request came from, as the hub saw it
  (it accepts a forwarded address only from a configured proxy, never from a
  header anyone can send), with **your browser's** address beside it. A
  different address is normal when the terminal runs on another machine, such
  as a server, a VM or a container. If you didn't start the sign-in, check this
  first.
- **Host name** and **client**: what the terminal reported. The terminal chose
  these, so they prove nothing, but a mismatch should still make you look
  twice.

**Deny** rejects the request, and the terminal learns at once. A code can be
approved or denied only once, and used only once.

## What the terminal gets

The terminal gets a **CLI session**: an ordinary row in the hub's session
store, of kind `cli`. It works like a browser session in every way:

- It **expires and idles out**: by default after 24 hours, or after 8 hours
  unused, like a browser session, and never later. An operator can shorten
  both (`ui.oidc.cli_session_ttl_hours`, `cli_idle_timeout_hours`).
- It **re-checks your roles with your identity provider** on the same schedule
  as a browser: in the background every `refresh_interval_minutes`, and before
  any action above operator once its claims are older than
  `max_claim_age_minutes`. If you are removed from a group at the provider, you
  lose what it gave you here within that time. The session can do this because
  the approval gave it its own grant at the provider.
- It is **listed** with its kind and host name in Settings → Active sessions
  and in `cloop hub session list`, and can be **revoked** from either, like any
  session.
- It **ends** when you sign out everywhere, when your account is offboarded, or
  when your identity provider disables you.
- Ending it **closes what it holds open** at once: a
  `cloop remote logs --follow` stops, and a `cloop task attach` terminal
  closes.

The terminal authenticates with `Authorization: Bearer cloop_cli_…` and in no
other way. The hub refuses a terminal's credential sent as a browser cookie,
and a browser's cookie sent as a terminal's credential.

## Using it

```console
$ cloop whoami
Hub:                   https://cloop.example.com
Signed in as:          Alice <alice@example.com> (00u1a2b3c4d5e6f7g8h9)
Session:               cli (dev-laptop), id 3b8f0a91c2d4
Role:                  operator
Expires in:            23h58m0s
Ends when unused for:  8h0m0s
Hub-wide permissions:  executor.read, project.read, run.start, run.stop, secret.own, secret.request, task.mutate, view.prefs
```

`cloop remote` works with the projects on the hub, acting as you. Each command
makes the same call as the dashboard, so it is allowed only when the matching
dashboard button would be. A viewer's `cloop remote run` is refused, as their
Start button is. Name a project by its name, its index or its path:

```console
$ cloop remote projects
IDX  NAME      STATUS   TASKS  PATH
0    api       running  12/31  /srv/projects/api
1    frontend  paused   4/9    /srv/projects/frontend

$ cloop remote tasks api --status pending
$ cloop remote add api "Add a /healthz endpoint" --description "200 and a JSON body"
Added task #32 to api: Add a /healthz endpoint
$ cloop remote run api
Started api. Follow it with: cloop remote logs api --follow
$ cloop remote logs api --follow
…the run's output, as it happens…
$ cloop remote stop api
```

Without `--follow`, `logs` prints the output the hub has for the current run
and exits. With `--follow`, it streams until you press `Ctrl-C`. If the hub
ends the stream because your session ended or your access to the project was
withdrawn, `logs` says so and exits with a non-zero status.

[`cloop task attach`](../operations/attach.md) uses the same session:

```console
$ cloop task attach 41                              # the default hub
$ cloop task attach 41 --hub https://other.example.com
```

Every command takes `--hub` to name another hub you are signed in to. For
scripts, every command still accepts an API token: `--token`, which takes
precedence over the stored session, or `CLOOP_API_TOKEN`. When `CLOOP_HUB_URL`
is set, `CLOOP_API_TOKEN` is the token for that hub. Otherwise it is used only
for a hub you have no session for, so a token exported for one hub is never
sent to another.

## From a checkout to a running project

The first thing to do on a hub is give it a project. `cloop remote init` creates
one from the checkout you are in, doing in one command what the dashboard's New
Project dialog, Repositories panel, Access Requests panel and Claude credential
card do:

```console
$ cd ~/src/widgets
$ cloop remote init --goal "Ship rate limiting for the public API" --executor edge-01 --access write --branch 'cloop/*' --run
Created widgets on https://cloop.example.com at /var/lib/cloop/projects/widgets, bound to executor edge-01.
Granted acme/widgets (write) through acme-github-app — grant grant_7f3a…, until 2026-10-13 09:14.
Granted your Claude credential alice-claude to its sandbox.
Dashboard: https://cloop.example.com/?project=%2Fvar%2Flib%2Fcloop%2Fprojects%2Fwidgets
Started widgets. Follow it with: cloop remote logs widgets --follow
```

What it does, in order:

1. **Reads the checkout's origin** and adds every `--repo owner/name`.
   `git@github.com:acme/widgets.git`, `https://github.com/acme/widgets`, an
   `ssh://` URL and GitHub's ssh-over-443 host all name `acme/widgets`. A
   remote that isn't on GitHub is refused (name the GitHub repositories with
   `--repo`). So is one that contains a credential, such as
   `https://<token>@github.com/…`: take the token out of the remote and revoke
   it. Nothing prints it.
2. **Checks what it can before creating anything**: that `--executor` is one an
   administrator has made available to you (`cloop remote executors` lists
   those), that every secret named with `--grant` exists, and that some GitHub
   credential can reach the repositories. If a check fails, nothing has been
   created.
3. **Creates the project** in the hub's projects root (`ui.projects_root`, by
   default `projects/` in the hub's home), named `--name` (by default the
   repository's name). The project is bound to the executor and holds the
   `--grant` credentials you may grant, all in one request that is applied in
   full or not at all. A directory that already holds a project is refused, so
   running `init` twice never wipes the first project. `--dir <path>` chooses
   the directory. A project's directory is what its sandboxes are given, so only
   an administrator may put one outside the projects root, and nobody may put
   one over the hub's own directory, another project, or the root itself.
4. **Attaches the repositories** through a GitHub App installation the hub
   holds, or a GitHub token of yours that the hub's
   [git proxy](../git-interception-proxy.md) guards. It tries your own
   installation first, then the organisation's where you may grant it, and asks
   each which repositories it can reach. `--repo-secret` picks one. Access is
   read-only unless you pass `--access write`, and `--branch` limits where
   pushes may go.
5. **Requests what you can't grant yourself.** For a credential that needs an
   approver, `init` files a request with `--justification` as the reason (by
   default, the goal), and prints the request's id and who can approve it.
6. **Sets up the Claude credential** that a sandboxed run signs in with. On an
   executor that isolates, `init` grants the credential you name with
   `--claude-secret`, or else your complete personal credential, if you have
   only one.
7. **Prints the project's dashboard link**, and with `--run` starts the first
   run. The link (`/?project=<path>`) opens the project, after signing the
   browser in if needed. Add `&tab=kanban` (or any tab's name) to open that tab
   instead of the Overview.

`--grant` gives the project any other stored credential, narrowed the way its
kind needs: `--grant staging-cluster,namespace=payments,namespace=staging`,
`--grant shared-proxy,host=api.example.com` or
`--grant npm,registry=npm.example.com`. Repeat a key for several values.
`ttl=` and `scope=` work with any kind.

If the project was created but something it needs is missing (a repository no
credential reaches, or a run that couldn't start because a request still waits
for its approver), `init` exits non-zero and says what, with the command that
adds it. With `--json`, it prints everything it did as one object.

The dashboard's other project actions have commands too:

```console
$ cloop remote executors                                   # where your projects may run
$ cloop remote repos list widgets                          # what it reaches, and through what
$ cloop remote repos add widgets acme/widgets-docs --access write
$ cloop remote repos remove widgets acme/widgets-docs      # narrows or revokes the grant
$ cloop remote grants request acme-github-app --project widgets --repo acme/infra \
      --justification "Terraform for the rate limiter (API-412)"
Requested acme-github-app (repos=acme/infra perms=contents:read) for project:/var/lib/cloop/projects/widgets — request req_9b1f…, waiting for an approver until 2026-10-15 09:14.
  Who can approve it: root@example.com (admin); members of group platform (admin); members of group leads (maintainer).
  Take it back with: cloop remote grants withdraw req_9b1f…
$ cloop remote grants list                                 # your requests, and who can approve the pending ones
$ cloop remote features start widgets "Rate limiting" --task "Token bucket" --task "429 with Retry-After"
$ cloop remote features list widgets
$ cloop remote features pr widgets rate-limiting           # push its branch and open the pull request
```

They all take `--json`. Each makes the dashboard's own call with your session,
so the hub refuses it whenever it would refuse the button. The error then says
what was needed and how to get it, instead of printing the hub's JSON:

```console
$ cloop remote init --goal "Ship widgets"
Error: your role does not permit this action (HTTP 403, FORBIDDEN)
  needs:      project.write (hub-wide)
  your role:  viewer (hub-wide)
  to get it:  ask an administrator of this hub to map your account to the maintainer role (Settings → Single sign-on → role mappings)
```

The role ladder in the [security model](../security/model.md) sets who may do
what. Creating a project and attaching repositories needs a maintainer.
Choosing the executor needs an administrator (`executor.manage`). Without that,
leave out `--executor` and the project runs on the hub's default. Requesting a
credential needs an operator.

## Sharing a Kubernetes cluster

If your cluster signs you in through a credential plugin (`kubelogin` on AKS,
`aws eks get-token` on EKS, or the GKE plugin), the hub can't use your
kubeconfig. The hub never runs a plugin, so the dashboard refuses the upload and
points you here. `cloop remote kube share` runs the plugin on your machine
instead, creates a ServiceAccount with only the access you choose, and stores
its token on the hub as your personal secret:

```console
$ cloop remote kube share aks-dev --context aks-dev --namespaces payments,payments-staging
Sharing context aks-dev (https://aks-dev-dns.hcp.westeurope.azmk8s.io:443) with https://cloop.example.com as "aks-dev":
  ServiceAccount  payments/cloop-aks-dev-3f9c2a1b (no token mounted into Pods)
  Read access     payments, payments-staging (RoleBinding cloop-aks-dev-3f9c2a1b -> ClusterRole view in each)
  …
Signing in to https://aks-dev-dns.hcp.westeurope.azmk8s.io:443 with kubelogin (Microsoft Entra ID, as on AKS)…
To sign in, use a web browser to open the page https://microsoft.com/devicelogin and enter the code …

Shared. https://cloop.example.com holds the token as your personal secret "aks-dev" (sec_9b1f…).
  Token expires   2026-10-13 09:14 UTC (in 23h59m)
  Renewal         by the hub, at half the token's life; `cloop remote kube list` shows it

$ cloop remote kube list                 # every share, when its token expires, who renews it
$ cloop remote kube renew aks-dev        # the next token now
$ cloop remote kube revoke aks-dev       # the ServiceAccount, its bindings and the hub's secret
```

A plugin that signs you in interactively uses this terminal, as it would under
`kubectl`. `--dry-run` shows what would be created without signing in at all.
Read access binds the cluster's `view` role in each namespace. `--access write`
binds `edit` and needs `--sa-namespace`: a namespace the share can't write to,
for the ServiceAccount to live in. The token lasts `--ttl` (10m to 7d, default
24h), or less if the cluster caps it. If the hub runs its Kubernetes access
monitor, it renews the token before it expires, and a run in progress picks up
the new one. Otherwise, `renew` it yourself. Then grant the secret to a project
in the dashboard's Secrets panel. The
[secrets guide](../guides/secrets.md#a-cluster-that-signs-you-in-through-a-plugin-aks-eks-gke)
lists every flag, and the
[architecture](../architecture/kubernetes-access.md#kubernetes-shares-a-cluster-behind-a-credential-plugin)
explains why each object is set up as it is.

## Signing out

```console
$ cloop logout
Signed out of https://cloop.example.com.
```

`logout` ends the session at the hub first, then deletes it from your machine,
so any copy of the credential elsewhere stops working too. If the hub can't be
reached, `logout` deletes nothing, because the session would stay valid at the
hub with no copy left to revoke it with. `--force` deletes it anyway. `--all`
signs out of every hub.

## Where the session is kept

Sessions are kept in `$XDG_CONFIG_HOME/cloop/hubs.json`
(`~/.config/cloop/hubs.json` if the variable is unset), written with mode
`0600` in a `0700` directory. There is one entry per hub: its URL, the session
credential, the session's public id, the `--ca-file` if you gave one, and who
you are signed in as.

If other users can read the file, cloop refuses to use it. Every command that
would send the credential stops with:

```
the credential file is readable by other users: /home/alice/.config/cloop/hubs.json
has mode 0644, so other users may have copied the session credentials in it.
Run `cloop logout --all` to revoke them at their hubs and delete the file, then
`cloop login` again
```

`cloop logout --all` still reads such a file, because its job then is to revoke
at the hubs whatever may have been copied. cloop never prints a credential: not
in `login`, not in `whoami`, and not in an error about the file.

## When it does not work

| You see | Because |
| --- | --- |
| `does not offer terminal sign-in: this hub has no single sign-on` | The hub authenticates with tokens, not SSO. Ask for an API token and pass it as `--token` or `CLOOP_API_TOKEN`. |
| `terminal sign-in is turned off on this hub` | The operator set `ui.oidc.device_login: false`. |
| `the code expired before it was approved` | Ten minutes passed. Run `cloop login` again. |
| `the sign-in was denied` | Someone pressed Deny, or the hub refused the approving account (for example, because of a deny binding after offboarding). |
| `the session … has ended (revoked, expired or idle)` | Run `cloop login` again. |
| `x509: certificate signed by unknown authority` | The hub's certificate is from a private CA: `cloop login <hub> --ca-file ca.pem`. |
| `warning: … is plain http to another machine` | The session credential would cross the network unencrypted. Use the hub's `https://` URL. |
| `This kubeconfig cannot be stored: user … signs in through …` (the dashboard) | The kubeconfig runs a credential plugin. Share the cluster from here instead: [`cloop remote kube share`](#sharing-a-kubernetes-cluster) |
| `a cloop project already exists at …` (from `cloop remote init`) | A project with that name is already on the hub, perhaps from an earlier `init`. Open it (`cloop remote projects`), or give this one another name with `--name`. |
| `… cannot hold a new project: the directory is in use or protected by this hub` | The directory is taken or overlaps something the hub protects: a project you can't see, the hub's own directory, or another project being created. The error is the same for every cause, so it reveals nothing about the hub's host. Choose another `--name`. |
| `only an administrator places a project outside the hub's projects root` | `--dir` named a directory outside `ui.projects_root`. Leave out `--dir` to create the project by name inside the root, or give a `--dir` inside it. |
| `… is the hub's projects root` / `… contains the hub's projects root` | A project goes inside the root, never at it or above it. |
| `… predates creating a project by name` | The hub is older than `cloop remote init`. Say where on the hub the project goes with `--dir <path>`, or upgrade the hub. |
| `executor "…" is restricted and your account is not on its access list` | An administrator has limited who may use that executor. Ask one to add you, or choose one that `cloop remote executors` lists. |
| `answered with a sign-in code this terminal will not show` | The approval page the hub gave is not an `http(s)://` URL, or the response contained control characters. `cloop login` neither prints nor opens it, because a URL with another scheme, handed to the desktop, can start any program registered for that scheme. Check that the URL belongs to a cloop hub. |
| `note: this hub keeps no refresh grant for the session` | The hub has no `CLOOP_SECRET_KEY`, or the provider issued no refresh token. Your roles stay as they were at approval, and actions above operator need a new `cloop login` once the approval is older than `max_claim_age_minutes`. |
| The approval page says *not approved: you signed in at the identity provider as a different account* | The provider answered for a different account from the one signed in to the dashboard. Nothing was approved. Sign in to the provider as yourself and approve again. |

## For the hub's operator

Terminal sign-in is on wherever single sign-on is. Its settings are under
`ui.oidc` (see the [configuration reference](../reference/configuration.md#terminal-sign-in-cloop-login)):

```yaml
ui:
  oidc:
    device_login: true                    # false turns the two endpoints off
    cli_session_ttl_hours: 24             # default and ceiling: session_ttl_hours
    cli_idle_timeout_hours: 8             # default and ceiling: idle_timeout_hours
    device_approval_max_age_minutes: 120  # a sign-in older than this re-authenticates to approve; -1 never
    sudo_max_age_minutes: 120             # privileged actions need an approval this recent; -1 never
```

Each step is recorded in the audit trail: [`device.code_issued`](../reference/audit-events.md#device),
`device.approved` and `device.denied`, and the session's own
[`session.created`](../reference/audit-events.md#session) with `kind: cli`.
The endpoints are listed in the [HTTP API reference](../reference/http-api.md),
and the [threat model](../security/threat-model.md#①-browser--hub) describes
how this sign-in holds up against the attacks on it.

---

↩ [getting started](README.md) · [documentation map](../README.md)
