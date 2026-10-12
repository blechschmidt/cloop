# Working from a terminal

A hub with single sign-on is reached through a browser — and some of the work is
better done from a terminal: opening a shell in a running task's sandbox,
tailing a run's output next to your editor, adding a task without leaving it.
`cloop login` gives your terminal its own session on such a hub, approved from
the browser you are already signed in with. No administrator has to mint you a
token, and nothing long-lived is created: the terminal holds a session like your
browser's, on the same rules.

- [Signing in](#signing-in)
- [What the approval page is telling you](#what-the-approval-page-is-telling-you)
- [What the terminal gets](#what-the-terminal-gets)
- [Using it](#using-it)
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

Open the link in a browser signed in to the hub — on a desktop with a browser,
`cloop login` opens it for you; `--no-browser` stops it. If the browser is not
signed in, the hub sends it through your identity provider first and brings it
back. The page shows the code and where the request came from. Check the code
against your terminal, then press **Approve**:

```console
Signed in to https://cloop.example.com as alice@example.com.
The session lasts until 2026-10-12 09:14 UTC, or until it goes unused for 8h0m0s.
```

Approving takes you through your identity provider once more. Usually you see
nothing — the provider recognises you and sends the browser straight back — but
if you last signed in there more than two hours ago
(`ui.oidc.device_approval_max_age_minutes`), the provider asks you to sign in
again first. Approving a code mints a credential, so it gets a recent sign-in,
the way a forge's "sudo mode" does. "Last signed in" is the provider's word for
it where it gives one (`auth_time`), so signing out of the dashboard and back in
without typing a password does not reset it; a provider that gives none is
asked to re-authenticate when your dashboard session is that old.

| Flag | Does |
| --- | --- |
| `--ca-file <pem>` | Trust this PEM bundle for the hub's certificate — a hub behind an internal CA. Kept with the session, so later commands use it too |
| `--no-browser` | Print the link without opening a browser |
| `--default` | Make this hub the default for commands that name none. The first hub you sign in to is the default anyway |
| `--hostname <name>` | What the approval page calls this machine (default: its host name) |

The terminal polls the hub every five seconds while it waits. `Ctrl-C` gives up;
an unapproved code dies on its own after ten minutes.

## What the approval page is telling you

**Only approve a code you started yourself.** Approving signs *whoever is
running that terminal* in to the hub as you, with your permissions. The known
attack on this kind of sign-in is a code somebody else started, sent to you with
a plausible story — "please approve this so the deploy can continue". Nothing in
the protocol can tell that apart from your own code; the page can only show you
enough to notice:

- **The code.** It must be the one your terminal printed.
- **Requested from** — the address the request reached the hub from, as the hub
  saw it (a proxy's word for it is believed only from a configured proxy, never
  from a header anybody can send) — and **your browser's** address beside it.
  A different address is normal when the terminal is on another machine: a
  server, a VM, a container. It is the first thing to check if you did not start
  it.
- **Host name** and **client** — what the terminal reported. The terminal chose
  these, so they prove nothing; a mismatch is still worth noticing.

**Deny** tells the terminal no at once. A code is approved or denied once, and
used once.

## What the terminal gets

A **CLI session**: an ordinary row in the hub's session store, of kind `cli`.
Everything a browser session is, it is:

- It **expires and idles out** — by default after the same 24 hours and 8 unused
  hours a browser session does, and never later. An operator may make it
  shorter (`ui.oidc.cli_session_ttl_hours`, `cli_idle_timeout_hours`).
- It **re-checks your roles with your identity provider** on the same rule a
  browser does: in the background every `refresh_interval_minutes`, and before
  anything above operator once its claims are older than `max_claim_age_minutes`.
  Removed from a group at the provider, you lose what it gave you here within
  that bound. The approval gave the session a grant at the provider of its own,
  which is what makes this possible.
- It is **listed** in Settings → Active sessions and in `cloop hub session list`
  with its kind and host name, and **revoked** from either like any session.
- It **ends** when you sign out everywhere, when your account is offboarded, and
  when your identity provider disables you.
- Ending it **closes what it holds open**: a `cloop remote logs --follow` stops,
  and a `cloop task attach` terminal closes, at once.

It is authenticated as `Authorization: Bearer cloop_cli_…`, and only that way:
the hub refuses a terminal's credential presented as a browser cookie, and a
browser's cookie presented as a terminal's.

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

`cloop remote` works with the projects on the hub, as you. Every command is the
dashboard's own call, so it is allowed exactly when the dashboard's button would
be — a viewer's `cloop remote run` is refused as their Start button is. A
project is named by its name, its index or its path:

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

`logs` without `--follow` prints what the hub holds of the current run's output
and exits. With it, it streams until you press `Ctrl-C` — or until the hub ends
the stream because your session ended or your access to the project was
withdrawn, which it says, exiting non-zero.

[`cloop task attach`](../operations/attach.md) uses the session too:

```console
$ cloop task attach 41                              # the default hub
$ cloop task attach 41 --hub https://other.example.com
```

Every command takes `--hub` to name another hub you are signed in to, and still
accepts an API token for scripts: `--token`, which wins over the stored
session, or `CLOOP_API_TOKEN` — which is `CLOOP_HUB_URL`'s hub's token when that
is set, and otherwise used only for a hub you hold no session for, so a token
exported for one hub never travels to another.

## Sharing a Kubernetes cluster

If your cluster signs you in through a credential plugin — `kubelogin` on AKS,
`aws eks get-token` on EKS, the GKE plugin — the hub cannot use your kubeconfig:
it never runs a plugin, and the dashboard refuses the upload and points you
here. `cloop remote kube share` runs the plugin on your machine instead, creates
a ServiceAccount with only the access you choose, and stores its token on the
hub as your personal secret:

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

A plugin that wants to sign you in interactively gets this terminal, as under
`kubectl`; `--dry-run` shows what would be created without signing in at all.
Read access binds the cluster's `view` role in each namespace; `--access write`
binds `edit` and needs `--sa-namespace`, a namespace the share cannot write, for
the ServiceAccount to live in. The token lives `--ttl` (10m to 7d, default 24h),
or less if the cluster caps it. On a hub running its Kubernetes access monitor
the hub renews it before it expires, and a run in flight takes the new token up;
elsewhere `renew` it yourself. Then grant it to a project in the dashboard's
Secrets panel. The [secrets guide](../guides/secrets.md#a-cluster-that-signs-you-in-through-a-plugin-aks-eks-gke)
has every flag, and the [architecture](../architecture/kubernetes-access.md#kubernetes-shares-a-cluster-behind-a-credential-plugin)
why each object is shaped as it is.

## Signing out

```console
$ cloop logout
Signed out of https://cloop.example.com.
```

`logout` ends the session **at the hub first**, then deletes it here — so a copy
of the credential somewhere else stops working too. If the hub cannot be
reached it deletes nothing, because the session would stay valid at the hub
with no copy left to revoke it with; `--force` deletes it anyway. `--all` signs
out of every hub.

## Where the session is kept

`$XDG_CONFIG_HOME/cloop/hubs.json` — `~/.config/cloop/hubs.json` when the
variable is unset — written `0600` in a `0700` directory. One entry per hub:
its URL, the session credential, the session's public id, a `--ca-file` if you
gave one, and who you are signed in as.

**A credential file other users can read is refused, not used.** Every command
that would present it stops with:

```
the credential file is readable by other users: /home/alice/.config/cloop/hubs.json
has mode 0644, so other users may have copied the session credentials in it.
Run `cloop logout --all` to revoke them at their hubs and delete the file, then
`cloop login` again
```

`cloop logout --all` still reads such a file — its job there is exactly to
revoke at the hubs what may have been copied. Nothing in cloop prints a
credential: not `login`, not `whoami`, not an error about the file.

## When it does not work

| You see | Because |
| --- | --- |
| `does not offer terminal sign-in: this hub has no single sign-on` | The hub authenticates with tokens, not SSO. Ask for an API token and pass it as `--token` or `CLOOP_API_TOKEN`. |
| `terminal sign-in is turned off on this hub` | The operator set `ui.oidc.device_login: false`. |
| `the code expired before it was approved` | Ten minutes passed. Run `cloop login` again. |
| `the sign-in was denied` | Somebody pressed Deny — or the hub refused the approving account (a deny binding, for instance after offboarding). |
| `the session … has ended (revoked, expired or idle)` | Run `cloop login` again. |
| `x509: certificate signed by unknown authority` | The hub's certificate is from a private CA: `cloop login <hub> --ca-file ca.pem`. |
| `warning: … is plain http to another machine` | The session credential would cross the network unencrypted. Use the hub's `https://` URL. |
| `This kubeconfig cannot be stored: user … signs in through …` (the dashboard) | The kubeconfig runs a credential plugin. Share the cluster from here instead: [`cloop remote kube share`](#sharing-a-kubernetes-cluster) |
| `answered with a sign-in code this terminal will not show` | The approval page the hub named is not an `http(s)://` URL, or the answer carried control characters. `cloop login` neither prints nor opens it — handed to the desktop, another scheme can start any program registered for it. Check the URL is a cloop hub's. |
| `note: this hub keeps no refresh grant for the session` | The hub has no `CLOOP_SECRET_KEY`, or the provider issued no refresh token. Your roles are as of the approval, and actions above operator need a fresh `cloop login` once that is older than `max_claim_age_minutes`. |
| The approval page says *not approved: you signed in at the identity provider as a different account* | The provider answered for another account than the one signed in to the dashboard. Nothing was approved; sign in to the provider as yourself and approve again. |

## For the hub's operator

Terminal sign-in is on wherever single sign-on is. The settings are in
`ui.oidc` — see the [configuration reference](../reference/configuration.md#terminal-sign-in-cloop-login):

```yaml
ui:
  oidc:
    device_login: true                    # false turns the two endpoints off
    cli_session_ttl_hours: 24             # default and ceiling: session_ttl_hours
    cli_idle_timeout_hours: 8             # default and ceiling: idle_timeout_hours
    device_approval_max_age_minutes: 120  # a sign-in older than this re-authenticates to approve; -1 never
```

Each step is in the audit trail: [`device.code_issued`](../reference/audit-events.md#device),
`device.approved` and `device.denied`, and the session's own
[`session.created`](../reference/audit-events.md#session) with `kind: cli`.
The endpoints are in the [HTTP API reference](../reference/http-api.md), and
what the grant does against the attacks on it is in the
[threat model](../security/threat-model.md#①-browser--hub).

---

↩ [getting started](README.md) · [documentation map](../README.md)
