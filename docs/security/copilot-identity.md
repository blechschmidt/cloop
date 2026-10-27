# Per-person Copilot credentials

How a hub with single sign-on keeps each person's GitHub Copilot use on their
own seat — on runs on the hub's own host, the dashboard's model calls and the
runs the hub carries on by itself — and why that credential is a personal secret
rather than a login on the hub.

The `copilot` provider runs the GitHub Copilot CLI, which signs in with the
first credential it finds: `COPILOT_GITHUB_TOKEN`, `GH_TOKEN`, `GITHUB_TOKEN`,
the account `copilot login` stored under its home (`~/.copilot`), then the
GitHub CLI's. A run on the hub's own host inherits the hub's environment and
`HOME`. So until Task 20449, on a hub with more than one person on it, every
person's copilot run, every Split, Revise, blocker analysis and plan-assistant
call on a copilot project and every resume or failover of one signed in as
whoever the hub's environment named — the operator's `copilot login`, or a
`GH_TOKEN` the service holds for something else entirely — and the CLI wrote
everybody's sessions and logs, conversation included, into one directory.
[Per-user Claude Code logins](claude-code-identity.md) closed the same hole for
Claude (Tasks 20241, 20442 and 20443); this page is its Copilot counterpart.

There is no new configuration key: the switch is single sign-on itself. A hub
without it has one operator, whose sign-in is the one meant, and nothing here
changes for it.

- [The credential is a personal secret](#the-credential-is-a-personal-secret)
- [What it closes](#what-it-closes)
- [Granting it](#granting-it)
- [The Copilot home](#the-copilot-home)
- [What a run inherits](#what-a-run-inherits)
- [What is pinned, and how](#what-is-pinned-and-how)
- [Runs the hub carries on by itself](#runs-the-hub-carries-on-by-itself)
- [Shared credentials and callers with no identity](#shared-credentials-and-callers-with-no-identity)
- [Deprovisioning](#deprovisioning)
- [What keeps it that way](#what-keeps-it-that-way)
- [What this does not do](#what-this-does-not-do)

---

## The credential is a personal secret

Two designs were open: a per-person `COPILOT_HOME` signed in through a dashboard
flow, as the Claude login panel signs in a per-person Claude home; or the
person's own `COPILOT_GITHUB_TOKEN`, kept as their
[personal secret](model.md#personal-secrets) and granted to the
project. cloop uses the second, for four reasons:

| | |
| --- | --- |
| **At rest** | A personal secret is sealed by the secret broker (envelope encryption, the key-encryption key optionally held by a [KMS](../guides/secrets.md)), and no API ever returns its value. `copilot login` keeps a long-lived OAuth token in a file under the hub user's home, or in a keychain the hub's service rarely has — readable by anything running as that user. |
| **Everywhere** | One credential serves the hub's host and every sandbox: the same grant that signs a run on the hub's host in reaches a container, a Pod or an enrolled device, where a login on the hub's disk never could. The [sandbox preflight](claude-code-identity.md#checked-before-dispatch) already accepted exactly this. |
| **Lifecycle** | Offboarding destroys personal secrets and revokes their grants; a deactivation at the identity provider suspends the grants and takes them back from running workloads. A login file would need all of that built again. |
| **Spent by its owner only** | A personal credential counts only for runs its owner starts and is withheld from every other person's lease (`Requester.Withhold`). |

The per-person `COPILOT_HOME` exists all the same — for the CLI's sessions and
logs — and holds no credential.

The token must act for a person with a Copilot seat: a fine-grained personal
access token (`github_pat_…`) with the *Copilot Requests* permission, an OAuth
token (`gho_…`) or a GitHub App user token (`ghu_…`). A classic token (`ghp_…`)
is refused — the CLI does not accept one — and so are installation and refresh
tokens (`ghs_…`, `ghr_…`), which act for no person (`TestClassifyPastedGitHubTokens`).

---

## What it closes

| | Before, on a hub with single sign-on |
| --- | --- |
| **Whose seat** | Every person's copilot work ran on the hub operator's Copilot seat, or on a token the service held for something else — `GH_TOKEN` and `GITHUB_TOKEN` rank above the stored login. |
| **Somebody else's token** | A wildcard repository grant puts its token in `GH_TOKEN` and `GITHUB_TOKEN` (see [secrets](../guides/secrets.md)); a run whose own Copilot credential was missing would sign the CLI in with it. |
| **Where it is sent** | `GH_HOST`, `COPILOT_GH_HOST`, `COPILOT_API_URL` and the bring-your-own-key variables in the hub's environment said where the CLI presents a credential. |
| **Conversations** | `~/.copilot` held every person's sessions and logs in one directory. |
| **No credential** | A person who had none was served on the hub's. |

---

## Granting it

A copilot project on the hub's own host has the same *Copilot credential* card
on its Overview that a sandboxed one has, and on a hub with single sign-on it is
the viewer's own: it says whether *their* runs would sign in, and with what.
Paste a token there and it is stored as your personal secret and granted to the
project (a feature's grant goes to its parent), for 30 days unless you choose
otherwise; or pick a personal secret you already have. From a shell:

```bash
cloop secret grant <secret> --to project:/path/to/project --env-keys COPILOT_GITHUB_TOKEN
```

A run, a model call or a replay by someone with no credential that counts for
them is refused before anything starts, with the `409 harness_credential_missing`
the dashboard opens that dialog on; the body carries `per_person: true` and a
short `summary`. Nothing falls back to the hub's sign-in.

A [bring-your-own-key](../getting-started/providers.md#github-copilot) grant —
`COPILOT_PROVIDER_BASE_URL` with its key — counts as well: the run then talks to
that provider, on that key.

---

## The Copilot home

A person's Copilot home is `copilot/` inside their identity home — the private
directory their [Claude Code login](claude-code-identity.md#where-the-credential-lives)
lives in, under `~/.config/cloop/claude-identities/<slug>/` of the user the hub
runs as. One tree on purpose: everything that removes the identity home removes
this one — an offboarding on every hub member, the hourly sweep of denied
identities' homes, a deletion at the identity provider — and a legal hold that
keeps the one keeps the other.

It is made `0700` when its owner starts something on a copilot project. A
symbolic link where it belongs is refused rather than followed. A run the hub
carries on by itself finds it, and makes only the `copilot/` directory inside an
identity home that is already there: it never recreates the home of someone
offboarded. A dispatch acting for no one uses `copilot-unattributed/` beside the
identity homes — never the hub user's own `~/.copilot`.

---

## What a run inherits

The hub decides whom a dispatch acts for; the provider spawns the CLI, often in
another process — the `cloop run` the hub started. They meet in the environment
(`pkg/copilotauth`):

1. **Before the lease**, the hub appends an empty assignment of every one of
   the Copilot CLI's own variables in its environment — every `COPILOT_*` and
   `GITHUB_COPILOT_*` variable. Exec keeps the last assignment of a key, and the
   CLI reads an empty one as unset. Nothing but the CLI reads them; the GitHub
   tokens and host stay for the run's other tools, and step 4 takes them from
   the CLI.
2. **The lease** then delivers the project's grants as it always has — the
   person's own, or one shared with the project; another person's personal
   credential is withheld.
3. **After everything else**, the hub pins `CLOOP_COPILOT_HOME` to the person's
   Copilot home. Last, so that no grant — not even one of the person's own
   that names the variable — can point a run at somebody else's home
   (`TestAGrantCannotRepointACopilotRunsHome`).
4. **The provider**, seeing `CLOOP_COPILOT_HOME`, builds the CLI's environment
   from scratch: every `COPILOT_*`, `GITHUB_COPILOT_*`, `GH_TOKEN`,
   `GITHUB_TOKEN`, `GH_ENTERPRISE_TOKEN`, `GITHUB_ENTERPRISE_TOKEN`, `GH_HOST` and
   `GH_CONFIG_DIR` it inherited is removed, not merely blanked; the run's own
   credential is passed back — `COPILOT_GITHUB_TOKEN`, or a provider's URL with
   what travels beside it, never `COPILOT_PROVIDER_API_KEY_COMMAND`, which runs a
   command, nor a variable that names a host; `COPILOT_HOME` is the person's,
   and `GH_CONFIG_DIR` an empty directory inside it, so neither the CLI's stored
   login nor the GitHub CLI's can stand in for a missing credential. A run with
   no credential left, or whose home is gone, is refused before the CLI starts.

With the real CLI against a stand-in model server, a pinned run signs in to the
model with the person's key, keeps its session and logs in their home and none
in the hub's, and its shell sees none of the hub's tokens, hosts or settings
(`TestRealCLIPinnedToAPersonRunsAsThemOnly`; it runs where the CLI is installed —
set `CLOOP_COPILOT_CLI` — and is skipped in CI, which has none). With a
recording stub in its place: `TestAPinnedRunSignsInAsItsPersonOnly`,
`TestAPinnedRunWithNoCredentialNeverStartsTheCLI`,
`TestAPinnedRunWhoseHomeIsGoneIsRefused` and
`TestAPinnedInlineCallTakesItsCredentialFromTheCall`.

---

## What is pinned, and how

| Work | Acts for | How |
| --- | --- | --- |
| A run on the hub's host — Run, the Tasks tab's run bar, a new project's first run | the person who started it | the dispatch's clearance (`harnessClearanceFor`) settles the credential and hands the dispatch the blanks and the pin (`TestCopilotHostRunActsForItsPerson`) |
| The Split preview, Revise, the blocker analysis and the plan assistant | the caller | dispatched to the project's executor as helper subcommands since Task 20442, under the same clearance (`TestCopilotModelCallsActForTheCaller`) |
| The review gate's reviewer | the run's person | it runs inside the run's own `cloop run`, so it inherits the run's pinned environment — on any project: every harness dispatch to the hub's host is pinned whatever its own provider, since a `claudecode` project's reviewer may be `copilot`. Only a `copilot` project needs a Copilot credential to be dispatched at all; a reviewer with none fails its review rather than signing in as the hub. The card of a project whose own provider is another grants that provider's credential, so grant a reviewer's `COPILOT_GITHUB_TOKEN` from the Secrets panel or with `cloop secret grant` (`TestEveryHostRunIsPinnedWhateverItsProvider`) |
| The provider-call replay and the inline task replay | the caller | they run the provider in the hub's own process; `inlineHarnessEnv` pins every such call on a hub with single sign-on to the caller's Copilot home, whatever provider it names, and when one of them is `copilot` — spelled any way, as the provider factory reads names without regard to case — settles the caller's credential against the project's executor and leases it for the call alone |
| The automatic resume, its hand-off to another hub member, and a failover's replacement | the run's recorded starter | [below](#runs-the-hub-carries-on-by-itself) |

A copilot project bound to an executor that isolates from the hub was already a
per-person matter: a sandbox gets only what is granted to its project, and a
personal grant counts only for its owner's runs. Nothing about that changes.

End to end: `TestHubCopilotActsForThePersonEndToEnd` runs a hub with single
sign-on (`internal/ssohubtest`) whose own environment carries a Copilot token,
GitHub tokens and a GitHub host, dispatching the real `cloop run` and the real
subcommands to the test binary, with a stub `copilot` that records what each
call signed in with. Alice's and Bob's model calls, Alice's run, Bob's replay of
a call of Alice's and the automatic resume of Alice's run each sign in with that
person's own token, in their own Copilot home, with nothing of the hub's; Carol,
who granted nothing, is refused every one of them, and the CLI never runs for
her.

---

## Runs the hub carries on by itself

The automatic resume after a usage cap, the member a leader hands it to, and a
failover's replacement act for the person who started the run they continue,
exactly as for [Claude](claude-code-identity.md#resumed-and-failed-over-runs):
their credential must count for them, and their Copilot home must still be
there. When it is not — their grant revoked or expired, suspended at the
identity provider, their identity home gone — the dispatch is refused before
anything is leased, and the run waits paused `starter_unavailable`, naming them:
*has no Copilot credential on this hub that the hub may use for them*. It is
not carried on on a timer, nor on anyone else's credential: whoever presses Run
starts it as themselves (`TestCopilotResumeActsForItsStarter`,
`TestResumeClearanceFindsTheStartersCopilotHome`).

---

## Shared credentials and callers with no identity

A credential an administrator grants to the project as a shared secret counts
for every person's runs, as it does in a sandbox: it is an explicit decision
that the project's work bills that seat. Each person's run still keeps its
sessions in their own Copilot home (`TestCopilotHostRunOnASharedCredential`).

A caller that acts for no one — the static admin token, an API token minted on
nobody's behalf — has no personal credential, so only a shared one can sign its
runs in; without one they are refused. Unlike a Claude run, such a run is never
served on the hub's own sign-in (`TestPreflightCopilotOnTheHubsHost`).

---

## Deprovisioning

**Offboarding** (`cloop hub user offboard`, the dashboard, a deletion at the
identity provider) destroys the person's personal secrets — their Copilot
credential among them — revokes every grant over them, and removes their
identity home on every hub member, the Copilot home inside it with it. Under a
legal hold the secret and the home are kept, and the grants still revoked
(`TestSeveringTheIdentityHomeTakesTheCopilotHomeWithIt`).

**A deactivation at the identity provider** suspends the person's grants in the
same transaction that ends their sessions and tokens, and takes the credential
back from every running workload holding it. From then on it counts for no run:
theirs are refused, and the hub carries none on for them. The secret itself
stays sealed while they are suspended, as every personal credential does,
because an identity provider reactivates people; it is destroyed when the
provider deletes them, or when the deactivation outlasts
`ui.oidc.scim.offboard_after_days` (`TestSCIMReachesACopilotCredential`).

---

## What keeps it that way

- `tests/arch` holds every function that leases to taking the clearance's
  Copilot environment between settling the clearance and leasing, and to using
  the pin after the lease; and allows a dispatch under a *lease* clearance —
  which checks nothing and pins no Copilot account — only from listed callers
  whose workload calls no model (`TestEveryLeaseTakesTheCopilotPin`,
  `TestCopilotGateFlagsWhatItShould`). It sits beside the nil-resolver gate that
  pins Claude (`TestEveryDispatchPinsAClaudeAccount`).
- `tests/security` requires every spawn of the copilot binary to take its
  environment from the one builder that applies the per-person mode
  (`TestEveryCopilotSpawnPinsItsEnvironment`); pins what that mode strips
  (`TestCopilotPinningStripsWhatTheCLISignsInWith`); and extends the call-graph
  analysis: an HTTP handler that can run the Copilot CLI in the hub's own
  process — not through an executor — must be listed and must pin its caller
  with `inlineHarnessEnv`, and the hub's background reaches it nowhere
  (`TestHandlersRunningTheCopilotCLIPinTheirCaller`,
  `TestCopilotInlineCheckFlagsWhatItShould`).

---

## What this does not do

- **The hub's host is not a boundary between people.** A run on the hub's own
  host runs as the user the hub runs as. Its agent can read that user's files —
  other people's identity homes among them — and the environment of other runs
  on the host. Pinning keeps every run on its own person's credential by
  construction; it does not stop a person's agent from going looking. Where
  people must be isolated from each other's agents, bind the project to an
  executor that isolates from the hub.
- **The token is in the run's environment.** The Copilot CLI keeps
  `COPILOT_GITHUB_TOKEN` out of the commands its agent runs, but other processes
  of the run — hooks, a verification script — inherit it, as they inherit a
  sandbox's leased credentials.
- **`gh` in the agent's shell is not signed in** on a pinned run: `GH_TOKEN` and
  `GITHUB_TOKEN` are removed from the CLI's environment, a repository grant's
  included, and its GitHub CLI configuration is empty. The agent reaches the
  repositories it was granted through git, whose credential helper the grant
  installs.
- **The pin is inherited.** Everything a person's run starts inherits
  `CLOOP_COPILOT_HOME` — a `cloop run` or a `copilot` its agent starts in a
  shell included — so a Copilot CLI anywhere under that run signs in as that
  person or not at all. A developer running cloop's own test suite inside
  such a run is not affected (`internal/hometest` clears it); one running a
  copilot rig of their own there is, and refused without a credential leased
  to it.
- **No usage caps and no model relay.** Claude Code's subscription caps and the
  [model relay](claude-code-identity.md#behind-the-model-relay-the-credential-stays-on-the-hub)
  are Claude's; a copilot run's model calls go to GitHub, or to the project's
  own provider, directly.
