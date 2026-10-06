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
- [When the hub restarts](#when-the-hub-restarts)
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

### Every GitHub claim is a string

Before the grammar, the one fact that causes more broken rules than the rest of
this section combined:

**GitHub sends every one of its claims as a JSON string — `repository_id`,
`actor_id`, `run_id`, `run_number`, `run_attempt` and `ref_protected`
included.** Only the standard JWT time claims (`iat`, `exp`, `nbf`) are JSON
numbers.

```
assertion.repository_id == "123456"    # correct
assertion.repository_id == 123456      # never matches: refused as a type error
assertion.ref_protected == "false"     # correct — a stringified boolean
assertion.ref_protected == false       # never matches
```

The second and fourth lines are the natural thing to write and they cannot
work. They are refused rather than silently evaluating false, so the rule
editor's **Test** button tells you immediately — but no amount of re-reading
the expression reveals the problem, because the expression is not what is
wrong.

### The supported subset

This is a **strict subset** of CEL, and what it leaves out is as important as
what it keeps.

| Supported | Written as |
| --- | --- |
| claim selection, nested | `assertion.repository`, `assertion.ctx.env` |
| string literals, single or double quoted | `"acme/tool"`, `'acme/tool'` |
| decimal integer literals | `123456` |
| boolean literals | `true`, `false` |
| homogeneous list literals, trailing comma allowed | `["main", "release",]` |
| equality | `==`, `!=` |
| list membership | `in` |
| boolean connectives and grouping | `&&`, `\|\|`, `!`, `(` `)` |
| four string methods | `startsWith`, `endsWith`, `contains`, `matches` |

`&&` binds tighter than `||`, as in CEL. Comparisons do not chain: `a == b == c`
is refused, because CEL reads it as `(a == b) == c` and nobody means that.

`matches()` takes a **literal** regular expression — not a computed one — so a
pattern that does not compile is caught when you save the rule rather than when
a pipeline presents a token. It is RE2, unanchored (a search, not a full
match), and supports inline flags like `(?i)`.

### What is refused, and when

Everything below is **refused when you save the rule**. That is the entire
point: a construct this evaluator does not implement must never be a construct
it *misreads*.

| Refused | Write instead |
| --- | --- |
| `<` `>` `<=` `>=` | nothing — ordering has no use over identity claims |
| `+` `-` `*` `/` `%`, unary minus | nothing |
| `? :` ternaries | `&&` / `\|\|` |
| `has(assertion.x)` | pin the claim you want: `assertion.x == "…"` |
| macros — `all`, `exists`, `exists_one`, `map`, `filter` | one narrow rule per case |
| `size()`, `lowerAscii()`, and every function outside the four above | `matches("(?i)…")` for case folding |
| indexing — `assertion.groups[0]` | `"eng" in assertion.groups` |
| map literals and `in` over a map — `"k" in assertion.ctx` | `assertion.ctx.k == "…"` |
| float and hex literals — `1.5`, `0x10` | decimal integers |
| `null`, and `true`/`false`/`null` as field names | — |
| mixed-type list literals — `["123456", 999]` | one type per list (see below) |
| `//` comments | the rule's **name** field |
| durations, timestamps, optional chaining, type coercion | — |

Several of these are legal CEL that this evaluator declines. `size()`,
indexing, `has()`, macros and ternaries all *work* in real CEL; refusing them
keeps the policy readable by eye, which is the property an audit reader needs.
If you need one of them, you are describing a policy that should be several
narrow rules.

### Where this deliberately disagrees with CEL

If you know CEL, these five are the surprises. Every one of them makes this
evaluator **stricter** than CEL — it refuses where CEL would reach a verdict —
and that direction is deliberate: a refusal costs you a clearer error message,
whereas the opposite would admit a pipeline you did not intend.

- **A missing claim is an error, not `false`.** A rule reading
  `assertion.environment` against a job that declared no environment does not
  quietly fall through to its remaining conditions. It becomes undecidable, the
  rule is skipped, and the reason is recorded.
- **Cross-type comparison is an error, including under `!=`.** In CEL,
  `assertion.repository_id != 123456` is *true* for GitHub's string claim —
  the types differ, so they are unequal. Here it is a refusal. A negated
  condition over a mistyped claim is the one shape where CEL's answer is
  "admit".
- **No commutative absorption.** CEL lets `<error> || true` be `true` and
  `<error> && false` be `false`, so that operand order does not matter. Here a
  reached error propagates. `assertion.environment == "prod" || assertion.repository == "acme/tool"`
  admits under CEL and is undecidable here when the token carries no
  `environment`. Put the claim that is always present first, or split the rule.
- **A claim that is present but `null` is an error**, not a value that compares
  unequal to everything.
- **A mixed-type list literal is refused when you save the rule.** CEL's own
  checker rejects `"123" in [123]`, but it accepts `assertion.x in [123, "123"]`
  where the claim's type is not known statically. Here both are refused,
  because a comparison across types cannot be decided and the alternative is
  worse than a refusal: it would make the verdict depend on the order you typed
  the entries in. `assertion.repository_id in ["123456", 999]` would admit —
  the match is found before the `999` is reached — while
  `assertion.repository_id in [999, "123456"]` would not. Same allowlist, same
  intent, two different outcomes, and reordering a list silently changes who
  gets in.

The subset's conformance against the reference CEL implementation is machine-
checked: `pkg/celmatch/testdata/conformance.json` is a corpus of expressions
and claim sets, `testdata/cel-verdicts.json` records what real `cel-go` does
with each, and `testdata/conformance-table.txt` is the resulting side-by-side.
Every row where the two disagree is the subset being stricter, and a test fails
if that ever stops being true.

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
      set -euo pipefail
      : "${ACTIONS_ID_TOKEN_REQUEST_URL:?the job needs permissions: id-token: write}"
      ID_TOKEN=$(curl -fsS -H "Authorization: Bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
        "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=cloop" | jq -er .value)
      RESP=$(curl -sS --fail-with-body -X POST https://cloop.example.com/api/ci/token \
        -H 'content-type: application/json' \
        -d "{\"token\":\"$ID_TOKEN\"}") || {
        echo "::error::cloop issued no session: $(jq -r '.error | .message? // .' <<<"$RESP" 2>/dev/null)"
        exit 1
      }
      TOKEN=$(jq -er .token <<<"$RESP")
      BASE_URL=$(jq -er .base_url <<<"$RESP")
      echo "::add-mask::$TOKEN"
      echo "ANTHROPIC_BASE_URL=$BASE_URL" >> "$GITHUB_ENV"
      echo "ANTHROPIC_AUTH_TOKEN=$TOKEN" >> "$GITHUB_ENV"
  - name: Run the agent
    # a model the rule admits: Claude Code's own default can be one the allowlist refuses
    run: npx -y @anthropic-ai/claude-code --model sonnet -p "review the diff and fix any bug you find"
```

`permissions: id-token: write` is the line people forget. Without it
`$ACTIONS_ID_TOKEN_REQUEST_URL` is unset, and the step stops on its second line,
before it reaches the hub, with a message that names the missing permission.

The step fails, rather than carrying on, whenever federation does. A `run:`
step without a `shell:` runs under `bash -e`, which ignores a failed `curl` on
the left of a pipe, and `jq -r` prints `null` for a field an error body does
not have. Without `set -euo pipefail`, `curl -f` and `jq -e`, a refused
exchange exports `ANTHROPIC_BASE_URL=null`, the step goes green, and the job
fails one step later with Claude Code's `Invalid URL` — which names neither the
allowlist nor the permission. With them, the job stops at the exchange and
shows the hub's one-sentence reason.

The `::add-mask::` matters: it stops the session token appearing in the job log
if a later step echoes the environment.

`--model sonnet` matters too. Without it Claude Code picks its own default, and
that changes between releases: 2.1.81 asks for `claude-sonnet-4-6`, while
2.1.282 asks for `claude-opus-5-5`, which the hub's default allowlist (Sonnet
and Haiku, see [Turning it on](#turning-it-on)) refuses on the agent's first
call. `npx -y` runs whichever release is newest, so a job that relies on the
default can break with nothing changed on either side. Name a model your rule
admits — to let a pipeline use Opus, list it in the rule's `models`.

Nothing about the harness needs to know it is not talking to Anthropic. Claude
Code reads `ANTHROPIC_BASE_URL` and `ANTHROPIC_AUTH_TOKEN`; the SDKs read
`ANTHROPIC_BASE_URL` and `ANTHROPIC_API_KEY`, and the relay accepts either
credential header.

**Tokens are single use.** A GitHub OIDC token stays valid for several minutes
after the step that requested it, so one recovered from a debug log would
otherwise be replayable for the rest of its life. Exchange it once; ask the
forge for a fresh one if you need another.

This workflow is run end to end by `tests/ciworkflow`: a shell plays the
GitHub runner and a stand-in plays GitHub's token service, while the hub and
Claude Code are real. The test takes the snippet from the Settings panel and
fails if this page publishes different text.

## What a session may do

| Bound | Default | Set by |
| --- | --- | --- |
| models | the hub's `default_models` | rule `models` |
| requests | 500 | rule `max_requests` |
| `max_tokens` per call | 32000 | rule `max_output_tokens` |
| lifetime | 60 min (max 6 h) | rule `ttl_seconds` |
| API surface | `POST /v1/messages`, `POST /v1/messages/count_tokens`, `GET /v1/models`, `GET /v1/models/{id}` | fixed |

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
- **turning federation off**. Each hub instance keeps to its own switch, which
  its [instance overlay](../reference/configuration.md#two-dashboards-in-one-directory)
  may set. Off through Settings, it ends that process's sessions at once, and
  every member reading the same configuration ends its own within seconds.
  Off by editing the file, a process notices within 15 seconds. To stop every
  pipeline across a cluster whose members' overlays differ, disable or delete
  the rules instead: that ends their sessions wherever they are served.

Revocation stops the spend at once — every call after it is refused — but it
does not end the job at once. A revoked or expired session is answered with a
`401`, and Claude Code 2.1.282 retries that: eleven attempts over about three
minutes, then it exits with `Not logged in · Please run /login`. So a revoked
job holds its runner for those minutes and then fails with a message about
logging in, not about the revocation.

Every relay decision — allowed and denied, with the model and the token counts
— lands in the hub's audit trail as `ci.relay.allowed` / `ci.relay.denied`,
alongside `ci.exchange.accepted` / `ci.exchange.rejected` and the
`ci.rule.*` changes an operator made.

## When the hub restarts

A job outlives a restart of the hub it relays through — a nightly deploy, a
rolling update of a [hub cluster](../architecture/hub-cluster.md). Its session
is recorded when it is minted: the SHA-256 of its token, the rule and the
verified claims of the OIDC token it was minted for, its policy and what it has
spent. Never the token, and never the hub's Anthropic credential, which is the
hub's configuration and not the session's.

- A hub **stopped** gracefully suspends its sessions (`ci.session.suspended`)
  instead of ending them, and writes what each had spent. One **killed**
  outright leaves the same record, minus at most the last 15 seconds of its
  spend: the counters are flushed every 15 seconds.
- The job's next call reaches a hub process that has never heard of the
  session, and that process restores it on the spot (`ci.session.restored`) —
  no new token exchange, which the job could not make anyway: its OIDC token
  has been spent, and the replay guard refuses it a second time. The call has
  to present the session's token, which must hash to the record's; the record
  moves to that process by a conditional write, so of two members receiving a
  job's calls one restores the session and the other forwards to it.
- The restored session is held to **its rule as the rule stands now**:

  | Since the session was minted… | Its next call |
  | --- | --- |
  | its rule was deleted or disabled | `401`, and the session is closed |
  | its rule no longer admits the pipeline, or the hub's `issuer` or `audience` changed | `401`, and the session is closed |
  | its rule's models, `max_requests`, `max_output_tokens` or TTL were narrowed | served under the narrower policy |
  | its rule was widened | served under the policy it was minted with |

  Its request budget is what it had left, not a fresh one.

**Live sessions** lists a session no hub process serves right now as
*suspended*. **Revoke** ends its record, so the job's next call is refused
rather than restored. Editing or deleting its rule ends it too, and so does
turning federation off on the instance that served it — through Settings or
in the file, whether or not that instance is running: the hub ends such
records within a minute, and refuses to restore one before then. A suspended
session of an instance that keeps federation on is left alone.

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
| relay `401`, "session token was not accepted" | the session expired or was revoked, or a restarted hub found its rule no longer admits it — Claude Code retries for minutes, then says `Not logged in` |
| relay `403`, "model is not permitted" | the harness asked for a model outside the rule's allowlist |
| relay `429` | the session's request budget is spent |

The *undecidable rules* line is the one worth knowing about. From the
pipeline's side it looks identical to "no rule matched", and an operator who
cannot tell them apart will rewrite a rule that was nearly right.

In the job log, an exchange refusal is the federation step's
`cloop issued no session:` line, carrying the hub's one sentence. A relay refusal
is whatever the harness makes of it, and Claude Code makes it misleading: it
prints a relay `403` as `Failed to authenticate. API Error: 403 …`. Read
past the prefix — `model "…" is not permitted for this pipeline` is the
allowlist, not a bad credential.

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
