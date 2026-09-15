# Running an agent in CI without giving CI a key

How a GitHub Actions job runs Claude Code against your cloop hub's Anthropic
credential — without that credential ever reaching the runner, and without a
long-lived secret in the repository.

- [The problem](#the-problem)
- [How it works](#how-it-works)
- [Turning it on](#turning-it-on)
- [Allowlisting a pipeline](#allowlisting-a-pipeline)
- [Conditions](#conditions)
- [The workflow](#the-workflow)
- [What a session may do](#what-a-session-may-do)
- [Watching and revoking](#watching-and-revoking)
- [Debugging a refusal](#debugging-a-refusal)
- [Threat model](#threat-model)

---

## The problem

The obvious way to run an agent harness in CI is an `ANTHROPIC_API_KEY`
repository secret. It is also the wrong way, for four reasons that have nothing
to do with each other:

- the key is **long-lived**, so a leak is permanent until someone notices;
- it is **copied into every job** that can read the secret, including ones
  added later by someone who did not think about it;
- it **survives the job** that used it — a key exfiltrated from a runner works
  from anywhere, forever;
- nothing about a request made with it says **which pipeline** spent it, so
  "why did our bill triple" has no answer.

GitHub Actions can instead mint a short-lived, signed OIDC token that says what
the job *is* — repository, ref, workflow, environment, actor, event — and hand
it to a third party. cloop is the third party.

## How it works

```
GitHub Actions runner                         cloop hub                    Anthropic
        │                                         │                            │
        │ 1. mint OIDC token (audience: cloop)    │                            │
        │────────────────────────────────────────>│                            │
        │    POST /api/ci/token                   │  verify signature against  │
        │                                         │  token.actions.github…'s   │
        │                                         │  published keys            │
        │                                         │  match claims vs allowlist │
        │ 2. { base_url, token, expires_in }      │                            │
        │<────────────────────────────────────────│                            │
        │                                         │                            │
        │ 3. ANTHROPIC_BASE_URL=<base_url>        │                            │
        │    ANTHROPIC_AUTH_TOKEN=<token>         │                            │
        │    npx @anthropic-ai/claude-code …      │                            │
        │────────────────────────────────────────>│  check model, budget, path │
        │    POST /v1/messages                    │  attach the hub's key      │
        │                                         │───────────────────────────>│
        │<────────────────────────────────────────│<───────────────────────────│
```

The runner never holds the hub's Anthropic credential. It holds a session token
that is worth only what its rule says — these models, this many requests, this
long — and that the hub can revoke mid-job.

Trust is established in **two independent halves**, and both are required:

1. **Verification** proves the forge signed this token and minted it for this
   hub. On its own this proves nothing useful: every repository on GitHub can
   obtain a correctly signed token naming itself.
2. **Matching** proves you meant to trust the identity it describes. That is
   the allowlist below.

## Turning it on

Settings → **CI/CD pipelines**, or in `.cloop/config.yaml`:

```yaml
ui:
  ci:
    enabled: true
    audience: cloop          # what the workflow must request
    default_models:          # what a rule naming no models inherits
      - claude-sonnet-*
      - claude-haiku-*
```

The hub relays with `anthropic.api_key` — the credential the rest of cloop
already uses. Set `ui.ci.upstream_auth_token` instead if you relay with an
OAuth bearer, or `ui.ci.upstream_base_url` if you front the API with a gateway.

With `enabled: false` both endpoints refuse whatever rules are stored. That is
the switch to reach for when a pipeline is misbehaving and you want it stopped
now rather than after you have finished reading the allowlist.

> **A hub with federation on and no Anthropic credential answers every exchange
> with a 503.** The Settings panel says so before a pipeline finds out.

## Allowlisting a pipeline

A rule has two kinds of matcher and they compose with **AND**. The glob fields
cover what nearly every deployment needs:

| Field | Matches | Example |
| --- | --- | --- |
| `repository` | the `repository` claim | `acme/tool`, `acme/*` |
| `ref` | the `ref` claim | `refs/heads/main`, `refs/heads/**` |
| `workflow` | the display name, the `workflow_ref`, or that path without its `@ref` | `release`, `acme/tool/.github/workflows/release.yml` |
| `environment` | the `environment` claim | `production` |
| `actor` | who triggered the run | `dana` |
| `event_name` | the triggering event | `push` |

A trailing `/**` admits anything strictly below the prefix; a bare `*` does not
cross a `/`, same as everywhere else in cloop.

**Every rule must identify the repository.** A rule built only from `ref` and
`workflow` would admit any repository on GitHub whose workflow happened to be
called `release`, and would look, to whoever wrote it, like a rule about their
own repository. Rules like that are refused when you save them.

**The owner segment may not contain a wildcard.** `*/tool` reads like "the tool
repository" and means "any account that creates a repository called tool" —
which anyone can do, in seconds, for free.

`environment` deserves a note: a token only carries that claim when the job
declares an environment, so a rule that sets it never admits a job that did
not. That is the point — it makes GitHub's own environment protection rules
(required reviewers, branch restrictions) the approval gate in front of your
Anthropic spend.

## Conditions

For policies a glob cannot state, a rule may carry a CEL expression over the
token's claims:

```
assertion.repository == "acme/tool" && assertion.ref.startsWith("refs/heads/release/")
assertion.repository in ["acme/tool", "acme/other"]
assertion.repository == "acme/tool" && assertion.runner_environment == "github-hosted"
```

This is the same shape as Google's workload identity federation
`attribute_condition`, deliberately, because anyone federating GitHub Actions
has probably read those docs.

It is a **strict subset** of CEL, and what it leaves out is as important as
what it keeps:

| Supported | Not supported |
| --- | --- |
| string, int, bool and list literals | floats, hex, durations, timestamps |
| `assertion.<claim>`, nested selection | indexing, optional chaining |
| `==` `!=` `in` `&&` `\|\|` `!` and parentheses | `<` `>` `+` `-`, ternaries |
| `startsWith` `endsWith` `contains` `matches` | macros (`all`, `exists`, `map`), `size()`, any other function |

Anything outside that table is a **parse error when you save the rule**, not a
surprise when a pipeline is denied mid-release. `matches()` takes a literal
regular expression so a bad pattern is caught at the same moment.

Two semantics worth knowing, both chosen so the failure mode is refusal:

- **A missing claim is an error, not `false`.** A rule reading
  `assertion.environment` against a job that declared no environment does not
  quietly fall through to its remaining conditions — it becomes undecidable and
  is skipped, and the reason is recorded.
- **Cross-type comparison is an error.** `assertion.repository_id == "123"`
  does not silently evaluate false while you wonder why your rule never fires.

Use **Test** in the rule editor. It answers both questions a rule's author has
— does this compile, and would it admit the pipeline I am thinking of —
without pushing a commit.

## The workflow

The Settings panel renders this with your hub's URL and audience filled in;
copy it from there rather than from here.

```yaml
permissions:
  id-token: write   # required: lets the job mint an OIDC token
  contents: read

steps:
  - uses: actions/checkout@v5
  - name: Federate with cloop
    run: |
      ID_TOKEN=$(curl -sS -H "Authorization: Bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
        "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=cloop" | jq -r .value)
      RESP=$(curl -sS -X POST https://cloop.example.com/api/ci/token \
        -H 'content-type: application/json' \
        -d "{\"token\":\"$ID_TOKEN\"}")
      echo "ANTHROPIC_BASE_URL=$(echo "$RESP" | jq -r .base_url)" >> "$GITHUB_ENV"
      echo "::add-mask::$(echo "$RESP" | jq -r .token)"
      echo "ANTHROPIC_AUTH_TOKEN=$(echo "$RESP" | jq -r .token)" >> "$GITHUB_ENV"
  - name: Run the agent
    run: npx -y @anthropic-ai/claude-code -p "review the diff and fix any bug you find"
```

`permissions: id-token: write` is the line people forget. Without it
`$ACTIONS_ID_TOKEN_REQUEST_URL` is unset and the step fails before it reaches
the hub.

The `::add-mask::` matters: it stops the session token appearing in the job log
if a later step echoes the environment.

Nothing about the harness needs to know it is not talking to Anthropic. Claude
Code reads `ANTHROPIC_BASE_URL` and `ANTHROPIC_AUTH_TOKEN`; the SDKs read
`ANTHROPIC_BASE_URL` and `ANTHROPIC_API_KEY`, and the relay accepts either
credential header.

**Tokens are single use.** A GitHub OIDC token stays valid for several minutes
after the step that requested it, so one recovered from a debug log would
otherwise be replayable for the rest of its life. Exchange it once; ask the
forge for a fresh one if you need another.

## What a session may do

| Bound | Default | Set by |
| --- | --- | --- |
| models | the hub's `default_models` | rule `models` |
| requests | 500 | rule `max_requests` |
| `max_tokens` per call | 32000 | rule `max_output_tokens` |
| lifetime | 60 min (max 6 h) | rule `ttl_seconds` |
| API surface | `POST /v1/messages`, `POST /v1/messages/count_tokens`, `GET /v1/models` | fixed |

A `max_tokens` over the cap is **clamped, not refused** — a stock SDK
configuration must keep working behind a policy that sets one. A model outside
the allowlist is refused, and the hub's credential is never attached to that
request.

The API surface is fixed and narrow on purpose. Batches and files create state
that outlives the job and is billed to your account; the organization endpoints
are account administration. A pipeline lent the ability to ask a model a
question has not been lent the ability to enumerate the workspace paying for it.

## Watching and revoking

**Live sessions** on the Settings panel shows every federated pipeline, what it
has spent — requests, denials, input/output/cache tokens — and how much of its
budget is left. Each row links to the Actions run that owns it.

Three things revoke a session immediately, mid-job:

- **Revoke** on the session row;
- **editing or deleting its rule** — a session minted under the old text would
  otherwise keep spending under a policy that no longer exists;
- **turning federation off**.

Every relay decision — allowed and denied, with the model and the token counts
— lands in the hub's audit trail as `ci.relay.allowed` / `ci.relay.denied`,
alongside `ci.exchange.accepted` / `ci.exchange.rejected` and the
`ci.rule.*` changes an operator made.

## Debugging a refusal

A refused pipeline gets one sentence and no detail. That is deliberate: the
caller is unauthenticated by construction, so every word of explanation is a
word an attacker enumerating your hub gets for free.

The detail is in **Recent exchanges** on the Settings panel, which records every
attempt with the claims the token actually carried. The common causes:

| Symptom | Cause |
| --- | --- |
| `401`, "token was not accepted" | wrong `audience`, expired token, or the token was already exchanged |
| `403`, "not on the allowlist" | no rule matched — compare the recorded claims against your rule |
| `403` and the detail says *undecidable rules* | a rule reads a claim this token does not carry, usually `environment` |
| `503` | federation is off, or the hub has no Anthropic credential |
| relay `403`, "model is not permitted" | the harness asked for a model outside the rule's allowlist |
| relay `429` | the session's request budget is spent |

The *undecidable rules* line is the one worth knowing about. From the
pipeline's side it looks identical to "no rule matched", and an operator who
cannot tell them apart will rewrite a rule that was nearly right.

## Threat model

**What an attacker who controls a runner gets.** A session token, until it
expires or is revoked, bounded by its rule: those models, that many requests,
that output size. They cannot reach the hub's dashboard, any project, any other
secret, or any Anthropic endpoint outside the three listed above. They cannot
raise their own limits — the policy lives in the hub, not in the token.

**What an attacker who can open a pull request gets.** Nothing, unless a rule
admits `pull_request` events from forks. GitHub does not issue an OIDC token to
a fork PR workflow by default; if you widen that, widen it with a rule that
names the environment and let GitHub's environment protection do the approving.

**What an attacker who can merge to a matched branch gets.** Whatever the rule
grants, because at that point they *are* the pipeline. This is the boundary the
feature cannot move: pin `ref`, prefer `environment`, and keep budgets small.

**What a leaked session token gets.** The same as the runner, for the remainder
of its TTL — which is why the TTL defaults to an hour and is capped at six, and
why revocation is immediate rather than at expiry.

**What the hub's operator can still see.** Which pipeline spent what. Prompts
and completions are relayed, not inspected: the proxy moves bytes and decides
whether it should. The only fields it reads are the model name and
`max_tokens`, because those are the two that select and bound the spend.

---

Related: [secrets and egress](secrets.md) for the same bargain applied to
GitHub tokens and kubeconfigs · [security model](../security/model.md) ·
[HTTP API](../reference/http-api.md)
