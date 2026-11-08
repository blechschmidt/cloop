# Running an agent in CI without giving CI a key

A GitHub Actions job can run Claude Code with your cloop hub's Anthropic
credential. The credential never reaches the runner, and the repository needs
no long-lived secret.

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

The usual way to run an agent harness in CI is an `ANTHROPIC_API_KEY`
repository secret. That has four separate problems:

- The key is long-lived, so a leaked key works until someone notices.
- Every job that can read the secret gets a copy, including jobs someone adds
  later without thinking about it.
- The key outlives the job that used it. A key taken from a runner works from
  anywhere.
- A request made with the key doesn't say which pipeline sent it, so if your
  bill triples, you can't find out why.

Instead, GitHub Actions can mint a short-lived, signed OIDC token that
describes the job (its repository, ref, workflow, environment, actor and
event) and hand it to a third party: your cloop hub.

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

The runner never holds the hub's Anthropic credential. It gets a session token
that allows only what its rule allows (certain models, a number of requests,
a lifetime), and the hub can revoke it in the middle of a job.

The hub accepts an OIDC token only if it passes two separate checks:

1. **Verification** checks that the forge signed the token and minted it for
   this hub. That alone isn't enough, because any repository on GitHub can get
   a correctly signed token naming itself.
2. **Matching** checks that you chose to trust the identity in the token. That
   is the allowlist below.

## Turning it on

Turn federation on under Settings → **CI/CD pipelines**, or in
`.cloop/config.yaml`:

```yaml
ui:
  ci:
    enabled: true
    audience: cloop          # what the workflow must request
    default_models:          # what a rule naming no models inherits
      - claude-sonnet-*
      - claude-haiku-*
```

The hub relays requests with `anthropic.api_key`, the credential the rest of
cloop already uses. To relay with an OAuth bearer token, set
`ui.ci.upstream_auth_token` instead. If a gateway sits in front of the API,
set `ui.ci.upstream_base_url`.

With `enabled: false`, the token exchange and the relay both refuse every
request, whatever rules are stored. Use it to stop a misbehaving pipeline at
once, before you work out which rule to change.

> A hub with federation on but no Anthropic credential answers every exchange
> with a 503. The Settings panel warns about this before a pipeline runs into
> it.

## Allowlisting a pipeline

A rule can match on glob fields and on a condition, and a pipeline must satisfy
both. The glob fields cover what nearly every deployment needs:

| Field | Matches | Example |
| --- | --- | --- |
| `repository` | the `repository` claim | `acme/tool`, `acme/*` |
| `ref` | the `ref` claim | `refs/heads/main`, `refs/heads/**` |
| `workflow` | the display name, the `workflow_ref`, or that path without its `@ref` | `release`, `acme/tool/.github/workflows/release.yml` |
| `environment` | the `environment` claim | `production` |
| `actor` | who triggered the run | `dana` |
| `event_name` | the triggering event | `push` |

A trailing `/**` matches anything strictly below the prefix. A bare `*` doesn't
match across a `/`, as everywhere else in cloop.

**Every rule must identify the repository.** The hub refuses to save a rule
built only from, say, `ref` and `workflow`, because it would admit any
repository on GitHub with a workflow called `release`, although its author
probably meant only their own.

**The owner segment may not contain a wildcard.** `*/tool` looks like it means
"the tool repository", but it matches a repository called tool in any account,
and anyone can create one.

A token carries the `environment` claim only when the job declares an
environment, so a rule that sets `environment` never admits a job that doesn't.
That lets GitHub's environment protection rules (required reviewers, branch
restrictions) decide which jobs can spend on your Anthropic account.

## Conditions

For policies that globs can't express, a rule can carry a CEL expression over
the token's claims:

```
assertion.repository == "acme/tool" && assertion.ref.startsWith("refs/heads/release/")
assertion.repository in ["acme/tool", "acme/other"]
assertion.repository == "acme/tool" && assertion.runner_environment == "github-hosted"
```

They follow the form of the `attribute_condition` in Google's workload
identity federation, because anyone federating GitHub Actions has probably
read those docs.

### Every GitHub claim is a string

GitHub sends every one of its claims as a JSON string, including
`repository_id`, `actor_id`, `run_id`, `run_number`, `run_attempt` and
`ref_protected`. Only the standard JWT time claims (`iat`, `exp`, `nbf`) are
JSON numbers. Forgetting this breaks more rules than everything else in this
section together.

```
assertion.repository_id == "123456"    # correct
assertion.repository_id == 123456      # never matches: refused as a type error
assertion.ref_protected == "false"     # correct — a stringified boolean
assertion.ref_protected == false       # never matches
```

The second and fourth lines look natural but can never match. The hub reports
them as errors instead of evaluating them to false, so the rule editor's
**Test** button shows the problem straight away. Re-reading the expression
won't reveal it, because the expression itself looks right.

### The supported subset

Conditions use a strict subset of CEL. It supports the following:

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

`&&` binds tighter than `||`, as in CEL. Comparisons don't chain: `a == b == c`
is refused, because CEL reads it as `(a == b) == c`, which is almost never what
the author meant.

`matches()` accepts only a literal regular expression, so a pattern that
doesn't compile is caught when you save the rule, before any pipeline presents
a token. Patterns use RE2 syntax, are unanchored (they search the claim and
don't need to match all of it), and support inline flags such as `(?i)`.

### What is refused, and when

The hub refuses to save a rule that uses anything below. Because these are
caught at save time, the evaluator never misreads a construct it doesn't
implement.

| Refused | Write instead |
| --- | --- |
| `<` `>` `<=` `>=` | nothing: ordering is of no use for identity claims |
| `+` `-` `*` `/` `%`, unary minus | nothing |
| `? :` ternaries | `&&` / `\|\|` |
| `has(assertion.x)` | pin the claim you want: `assertion.x == "…"` |
| macros: `all`, `exists`, `exists_one`, `map`, `filter` | one narrow rule per case |
| `size()`, `lowerAscii()`, and every function outside the four above | `matches("(?i)…")` for case folding |
| indexing, such as `assertion.groups[0]` | `"eng" in assertion.groups` |
| map literals, and `in` over a map such as `"k" in assertion.ctx` | `assertion.ctx.k == "…"` |
| float and hex literals, such as `1.5` and `0x10` | decimal integers |
| `null`, and `true`/`false`/`null` as field names | nothing |
| mixed-type list literals, such as `["123456", 999]` | one type per list (see below) |
| `//` comments | the rule's **name** field |
| durations, timestamps, optional chaining, type coercion | nothing |

Some of these are valid CEL: `size()`, indexing, `has()`, macros and ternaries
all work in real CEL. Leaving them out keeps every policy easy to read for
whoever audits it. If you need one of them, write several narrow rules
instead.

### Where this deliberately disagrees with CEL

If you know CEL, these five differences may surprise you. In each one this
evaluator is stricter than CEL: it returns an error where CEL would reach a
verdict. That way a mistake in a rule costs you an error message, never a
pipeline admitted by accident.

- **A missing claim is an error, not `false`.** If a rule reads
  `assertion.environment` and the job declared no environment, the rule doesn't
  fall through to its remaining conditions. It becomes undecidable: the hub
  skips the rule and records why.
- **Cross-type comparison is an error, including under `!=`.** In CEL,
  `assertion.repository_id != 123456` is true for GitHub's string claim,
  because values of different types are unequal. Here it is an error. A negated
  condition over a mistyped claim is the one case where CEL's answer would be
  to admit the pipeline.
- **No commutative absorption.** In CEL, `<error> || true` is `true` and
  `<error> && false` is `false`, so that operand order doesn't matter. Here an
  error propagates as soon as evaluation reaches it.
  `assertion.environment == "prod" || assertion.repository == "acme/tool"`
  admits under CEL but is undecidable here when the token has no `environment`
  claim. Put the claim that is always present first, or split the rule.
- **A claim that is present but `null` is an error**, rather than a value that
  compares unequal to everything.
- **A mixed-type list literal is refused when you save the rule.** CEL's own
  checker rejects `"123" in [123]`, but it accepts `assertion.x in [123, "123"]`
  when the claim's type isn't known statically. Here both are refused. A
  comparison across types can't be decided, and allowing it would make the
  result depend on the order of the entries:
  `assertion.repository_id in ["123456", 999]` would admit, because the match
  is found before evaluation reaches `999`, while
  `assertion.repository_id in [999, "123456"]` would not. Reordering the list
  would change which pipelines get in.

A test checks the subset against the reference CEL implementation.
`pkg/celmatch/testdata/conformance.json` is a corpus of expressions and claim
sets, `testdata/cel-verdicts.json` records what the real `cel-go` does with
each, and `testdata/conformance-table.txt` shows the results side by side.
Wherever the two disagree, the subset is the stricter one, and the test fails
if that ever stops being true.

Use **Test** in the rule editor to check, without pushing a commit, whether a
rule compiles and whether it would admit the pipeline you have in mind.

## The workflow

Copy this workflow from the Settings panel, which shows it with your hub's URL
and audience filled in.

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

`permissions: id-token: write` is the line people forget. Without it,
`$ACTIONS_ID_TOKEN_REQUEST_URL` is unset, and the step stops at its second
line, before it contacts the hub, with a message naming the missing
permission.

If federation fails, the step fails too. A `run:` step without a `shell:` runs
under `bash -e`, which ignores a failed `curl` on the left of a pipe, and
`jq -r` prints `null` for a field that an error body lacks. Without
`set -euo pipefail`, `curl -f` and `jq -e`, a refused exchange would export
`ANTHROPIC_BASE_URL=null`, the step would pass, and the job would fail one
step later with Claude Code's `Invalid URL` error, which mentions neither the
allowlist nor the permission. With them, the job stops at the exchange and
shows the hub's one-sentence reason.

The `::add-mask::` line keeps the session token out of the job log if a later
step prints the environment.

Keep `--model sonnet` as well. Without it, Claude Code picks its own default
model, which changes between releases: 2.1.81 asks for `claude-sonnet-4-6`,
while 2.1.282 asks for `claude-opus-5-5`, which the hub's default allowlist
(Sonnet and Haiku, see [Turning it on](#turning-it-on)) refuses on the agent's
first call. `npx -y` runs the newest release, so a job that relies on the
default can break with no change on your side or the hub's. Name a model your
rule admits. To let a pipeline use Opus, add it to the rule's `models`.

The harness doesn't need to know that it is talking to the hub. Claude Code
reads `ANTHROPIC_BASE_URL` and `ANTHROPIC_AUTH_TOKEN`. The SDKs read
`ANTHROPIC_BASE_URL` and `ANTHROPIC_API_KEY`, and the relay accepts either
credential header.

**Tokens are single use.** A GitHub OIDC token stays valid for several minutes
after the step that requested it, so otherwise anyone who found one in a debug
log could replay it until it expired. Exchange each token once, and ask GitHub
for a new one if you need another.

`tests/ciworkflow` runs this workflow end to end against a real hub and real
Claude Code, with a shell in place of the GitHub runner and a fake of GitHub's
token service. The test takes the snippet from the Settings panel and fails if
this page shows different text.

## What a session may do

| Bound | Default | Set by |
| --- | --- | --- |
| models | the hub's `default_models` | rule `models` |
| requests | 500 | rule `max_requests` |
| `max_tokens` per call | 32000 | rule `max_output_tokens` |
| lifetime | 60 min (max 6 h) | rule `ttl_seconds` |
| API surface | `POST /v1/messages`, `POST /v1/messages/count_tokens`, `GET /v1/models`, `GET /v1/models/{id}` | fixed |

A `max_tokens` above the cap is clamped to the cap instead of refused, so a
stock SDK configuration keeps working under a policy that sets a cap. A request
for a model outside the allowlist is refused, and the hub never attaches its
credential to it.

The API surface is fixed and small. Batches and files create state that
outlives the job and is billed to your account, and the organization endpoints
administer the account. Permission to send prompts to a model doesn't let a
pipeline list the workspace that pays for them.

## Watching and revoking

**Live sessions** on the Settings panel lists every federated pipeline with
what it has spent (requests, denials, and input, output and cache tokens) and
how much of its budget is left. Each row links to the Actions run it belongs
to.

Three things revoke a session immediately, even in the middle of a job:

- **Revoke** on the session row.
- **Editing or deleting its rule.** Otherwise a session minted under the old
  rule would keep spending under a policy that no longer exists.
- **Turning federation off.** Each hub instance follows its own switch, which
  its [instance overlay](../reference/configuration.md#two-dashboards-in-one-directory)
  can set. Turning it off in Settings ends that process's sessions at once, and
  every member that reads the same configuration ends its own within seconds.
  If you turn it off by editing the file, a process notices within 15 seconds.
  To stop every pipeline in a cluster whose members have different overlays,
  disable or delete the rules instead. That ends their sessions on whichever
  member serves them.

Revoking a session stops its spending at once, because every later call is
refused, but the job keeps running for a while. The hub answers a revoked or
expired session with a `401`, and Claude Code 2.1.282 retries: eleven attempts
over about three minutes, after which it exits with
`Not logged in · Please run /login`. So a revoked job holds its runner for
those minutes and then fails with a message about logging in that doesn't
mention the revocation.

Every relay decision, allowed or denied, goes into the hub's audit trail as
`ci.relay.allowed` or `ci.relay.denied`, with the model and the token counts.
The trail also records `ci.exchange.accepted` and `ci.exchange.rejected`, and
the `ci.rule.*` changes operators make.

## When the hub restarts

A job keeps working when the hub it relays through restarts, for example for a
nightly deploy or a rolling update of a
[hub cluster](../architecture/hub-cluster.md). When the hub mints a session,
it records the SHA-256 of the session's token, the rule, the verified claims of
the OIDC token it was minted for, its policy and what it has spent. It never
records the token itself or the hub's Anthropic credential, which belongs to
the hub's configuration.

- A hub that is stopped gracefully suspends its sessions
  (`ci.session.suspended`) instead of ending them, and writes down what each
  has spent. A hub that is killed leaves the same record, minus at most the
  last 15 seconds of spending, because it flushes the counters every 15
  seconds.
- The job's next call reaches a hub process that doesn't know the session, and
  that process restores it on the spot (`ci.session.restored`). There is no new
  token exchange, and the job couldn't make one anyway: its OIDC token has
  been used, and the replay guard refuses it a second time. The call must
  present the session's token, whose hash must match the record. The record
  moves to that process with a conditional write, so if two members receive a
  job's calls, one restores the session and the other forwards to it.
- The restored session must satisfy its rule as the rule stands now:

  | Since the session was minted… | Its next call |
  | --- | --- |
  | its rule was deleted or disabled | `401`, and the session is closed |
  | its rule no longer admits the pipeline, or the hub's `issuer` or `audience` changed | `401`, and the session is closed |
  | its rule's models, `max_requests`, `max_output_tokens` or TTL were narrowed | served under the narrower policy |
  | its rule was widened | served under the policy it was minted with |

  Its request budget is what it had left, not a fresh one.

**Live sessions** shows a session that no hub process is serving right now as
*suspended*. **Revoke** ends its record, so the job's next call is refused
instead of restored. Editing or deleting its rule also ends it, and so does
turning federation off on the instance that served it, through Settings or in
the file, whether or not that instance is running. The hub ends such records
within a minute and won't restore one in the meantime. A suspended session of
an instance that keeps federation on is left alone.

## Debugging a refusal

A refused pipeline gets a one-sentence error and no detail. The caller hasn't
authenticated, so any detail in the error would also help an attacker probing
your hub.

The details are in **Recent exchanges** on the Settings panel, which records
every attempt with the claims its token carried. Common causes:

| Symptom | Cause |
| --- | --- |
| `401`, "token was not accepted" | wrong `audience`, expired token, or the token was already exchanged |
| `403`, "not on the allowlist" | no rule matched; compare the recorded claims with your rule |
| `403` and the detail says *undecidable rules* | a rule reads a claim this token does not carry, usually `environment` |
| `503` | federation is off, or the hub has no Anthropic credential |
| relay `401`, "session token was not accepted" | the session expired or was revoked, or a restarted hub found that its rule no longer admits it. Claude Code retries for minutes, then says `Not logged in` |
| relay `403`, "model is not permitted" | the harness asked for a model outside the rule's allowlist |
| relay `429` | the session's request budget is spent |

Look out for the *undecidable rules* case. From the pipeline's side it looks
the same as "no rule matched", and an operator who can't tell the two apart
may rewrite a rule that was nearly right.

In the job log, a refused exchange appears as the federation step's
`cloop issued no session:` line, followed by the hub's one sentence. How a
refused relay call appears depends on the harness, and Claude Code's message
is misleading: it prints a relay `403` as
`Failed to authenticate. API Error: 403 …`. Read past the prefix.
`model "…" is not permitted for this pipeline` means the rule's model
allowlist refused the request, not that the credential is bad.

## Threat model

**What an attacker who controls a runner gets.** A session token, until it
expires or is revoked, limited by its rule: those models, that many requests,
that output size. They can't reach the hub's dashboard, any project, any other
secret, or any Anthropic endpoint other than the ones listed above. They can't
raise their own limits, because the policy is kept in the hub, not in the
token.

**What an attacker who can open a pull request gets.** Nothing, unless a rule
admits `pull_request` events from forks. By default, GitHub doesn't issue an
OIDC token to a workflow running for a pull request from a fork. If you allow
that, do it with a rule that names an environment, and let GitHub's
environment protection rules approve each run.

**What an attacker who can merge to a matched branch gets.** Whatever the rule
grants, because they now control the pipeline. Federation can't protect
against this, so pin `ref`, prefer `environment`, and keep budgets small.

**What a leaked session token gets.** The same as the runner, for the rest of
its TTL. That is why the TTL defaults to an hour and is capped at six hours,
and why revocation takes effect immediately instead of at expiry.

**What the hub's operator can still see.** Which pipeline spent what. The hub
relays prompts and completions without inspecting them: the proxy forwards the
bytes and decides whether to forward them. The only fields it reads are the
model name and `max_tokens`, because those two choose and limit the spend.

---

Related: [secrets and egress](secrets.md), which applies the same approach to
GitHub tokens and kubeconfigs · [security model](../security/model.md) ·
[HTTP API](../reference/http-api.md)
