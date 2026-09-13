# Choosing and configuring a provider

A **provider** is the thing cloop talks to when it needs a model: a local CLI,
a hosted API, or a server on your own machine. Everything else — the plan, the
tasks, the executors — is the same whichever one you pick, so this is a
decision you can change later with one command.

- [The backends](#the-backends)
- [Setting one up](#setting-one-up)
- [Checking what is configured](#checking-what-is-configured)
- [How a provider is chosen](#how-a-provider-is-chosen)
- [How a model is chosen](#how-a-model-is-chosen)
- [Reasoning effort](#reasoning-effort)
- [Environment variables](#environment-variables)
- [Named profiles](#named-profiles)
- [Role-based routing](#role-based-routing)

---

## The backends

| Name | Talks to | Credential | Default model |
| --- | --- | --- | --- |
| `claudecode` | the `claude` CLI as a subprocess | whatever the CLI is already signed in with | none — the CLI decides |
| `anthropic` | `https://api.anthropic.com/v1` | `ANTHROPIC_API_KEY` | `claude-opus-4-6` |
| `openai` | `https://api.openai.com/v1` (Chat Completions) | `OPENAI_API_KEY` | `gpt-4o` |
| `ollama` | `http://localhost:11434` | none | `llama3.2` |

**`claudecode` is the default**, and it is the only backend that holds no
credential of its own. It runs the `claude` binary once per call, so it inherits
that CLI's existing sign-in — a Claude Code subscription rather than metered API
billing. cloop looks for `claude` on `PATH` first, then at
`~/.local/bin/claude`, `~/.npm-global/bin/claude` and `/usr/local/bin/claude`,
which is what makes it work when the dashboard is started from a service manager
with a thin environment. It reports no default model: cloop passes `--model`
only when one is set, and otherwise lets the CLI choose. "Existing sign-in"
means the machine's on a single-user install and the *requesting user's* on a
hub with SSO, where each identity has its own Claude login — see
[per-user Claude Code logins](../security/claude-code-identity.md).

**`anthropic`** is the same family of models over the HTTP API, billed per
token — the one to pick when you want an API key rather than a subscription.
**`openai`** speaks Chat Completions, and `openai.base_url` makes it speak it to
something else: any server implementing the same endpoint (Azure OpenAI, a
llama.cpp server, a gateway) is reachable that way, which is the supported route
for OpenAI-compatible backends. **`ollama`** needs no key at all and talks to a
server on your own machine, so nothing leaves it.

A fifth provider, **`mock`**, is accepted by `cloop config set provider` and by
`cloop run --mock`. It answers from `.cloop/mock_responses.yaml` (or
`mock.responses_file`) and defaults to returning `TASK_DONE`. It calls nothing
and costs nothing, which makes it right for testing a plan's shape or a CI
pipeline and wrong for anything else.

---

## Setting one up

Configuration lives in `.cloop/config.yaml`, written mode `0600` because it may
hold an API key. `cloop config set` is the safe way to edit it — it validates
each value before saving, and refuses an unknown key rather than writing it.

```bash
cloop config set provider anthropic
cloop config set anthropic.api_key sk-ant-...
cloop config set anthropic.model claude-opus-4-6
```

These are the provider keys the setter accepts, in full:

| Key | Notes |
| --- | --- |
| `provider` | one of `anthropic`, `openai`, `ollama`, `claudecode`, `mock` — anything else is rejected |
| `anthropic.api_key` / `.model` / `.base_url` | |
| `openai.api_key` / `.model` / `.base_url` | `base_url` is how you reach an OpenAI-compatible server |
| `ollama.base_url` / `.model` | |
| `claudecode.model` | |
| `claudecode.effort` | `low`, `medium`, `high`, `xhigh`, `max` — see [Reasoning effort](#reasoning-effort) |
| `mock.responses_file` / `mock.default` | |

Some provider settings exist in the file but have no setter, so they are edited
in `.cloop/config.yaml` directly: the inference parameters (`temperature`,
`top_p`, `max_tokens`, and `frequency_penalty` for OpenAI), the Claude Code
subscription caps (`claudecode.max_weekly_pct`, `max_five_hour_pct`,
`max_weekly_opus_pct`, `max_weekly_sonnet_pct` — also editable from the
dashboard), and
[`claudecode.background.*`](../reference/configuration.md#background-work-left-by-an-agent).

`cloop config show` prints the effective configuration with API keys masked.
Every save is also mirrored into `.cloop/state.db`, so `cloop config diff` and
`cloop config sync` exist to reconcile the two if they drift.

---

## Checking what is configured

```bash
cloop providers          # what is registered, what is configured, what is default
cloop providers --test   # ...and does it actually answer
```

The listing marks the default with `*` and shows each backend's endpoint and
resolved model. Read "configured" narrowly: it means *a credential is present*,
and `claudecode` and `ollama` are always reported as configured because neither
needs one. It is `--test` that proves anything — it builds each provider for
real and asks it to reply `OK`, with a 30-second timeout, so a missing `claude`
binary or an unreachable Ollama shows up as `FAIL` with the underlying error.

One caveat before you debug a surprise: `cloop providers` reads configuration
through the same loader as every other command, and that loader applies only the
unprefixed environment variables. A key exported as `CLOOP_ANTHROPIC_API_KEY` is
picked up by `cloop run` and **not** here — see
[Environment variables](#environment-variables).

---

## How a provider is chosen

`cloop run` resolves the name in this order, first non-empty answer wins:

1. **`--provider`** on the command line (`--mock` is shorthand for
   `--provider mock`).
2. **`provider:` in `.cloop/config.yaml`**, after `CLOOP_PROVIDER` and any
   `--profile` overlay have been applied to it.
3. **The provider persisted in project state** — set by `cloop init --provider`
   or by the dashboard's Provider picker.
4. **Auto-detection**: `ANTHROPIC_API_KEY` or `CLOOP_ANTHROPIC_API_KEY` selects
   `anthropic`; failing that, `OPENAI_API_KEY` or `CLOOP_OPENAI_API_KEY`
   selects `openai`; otherwise `claudecode`.

Step 2 almost always answers, which is worth understanding rather than being
surprised by: when `.cloop/config.yaml` is absent the loader returns built-in
defaults with `provider: claudecode` already filled in. Steps 3 and 4 are
therefore reached only when the file exists *and* its `provider:` key is empty —
so leave that key blank if you want the project's own saved provider to win.

The resolved name is written back into project state at the start of the run, so
the next `cloop run` with no flags repeats the same choice.

---

## How a model is chosen

Independently of the provider, and in this order:

| | Source |
| --- | --- |
| 1 | `--model` on the command line |
| 2 | `CLOOP_MODEL` in the environment |
| 3 | the per-provider key: `anthropic.model`, `openai.model`, `ollama.model`, `claudecode.model` |
| 4 | the model persisted in project state (`cloop init --model`, or the dashboard's picker) |
| 5 | the provider's own default |

The provider's own default is `claude-opus-4-6` for `anthropic`, `gpt-4o` for
`openai` and `llama3.2` for `ollama`. `claudecode` has none: with no model
resolved, cloop passes no `--model` to the CLI and the CLI's own default
applies.

The per-provider key is only consulted for the provider actually in use, so
setting `openai.model` changes nothing while the project runs on `anthropic` —
which is what lets you keep all four configured at once.

---

## Reasoning effort

`claudecode` accepts a reasoning-effort level, passed straight through to the
CLI as `--effort`. Valid values are `low`, `medium`, `high`, `xhigh` and `max`;
empty means the CLI's default.

```bash
cloop run --effort high
cloop config set claudecode.effort high     # the project-wide default
cloop init --effort high "…"                # saved into project state
```

Resolution is `--effort` > `claudecode.effort` in the config > the effort
persisted in project state. An invalid `--effort` is a hard error; an invalid
`claudecode.effort` in the file is reported on stderr and ignored, so a bad
value in YAML cannot make every CLI invocation fail.

The other backends ignore this setting entirely — only the `claudecode`
provider reads it. OpenAI's o-series models do get a `reasoning_effort`, but it
is derived separately from cloop's extended-thinking budget rather than from
`--effort`, and only for models whose name begins `o1`, `o3` or `o4-mini`.

---

## Environment variables

There are two sets, and they are not interchangeable. The first is applied by
the configuration loader, so it affects **every** command:

| Variable | Overrides |
| --- | --- |
| `CLOOP_PROVIDER` | `provider` |
| `ANTHROPIC_API_KEY` | `anthropic.api_key` |
| `ANTHROPIC_BASE_URL` | `anthropic.base_url` |
| `OPENAI_API_KEY` | `openai.api_key` |
| `OPENAI_BASE_URL` | `openai.base_url` |
| `OLLAMA_BASE_URL` | `ollama.base_url` |
| `GITHUB_TOKEN` | `github.token` |
| `CLOOP_OIDC_CLIENT_SECRET` | `ui.oidc.client_secret` |

The second set is applied by `cloop run` only, on top of the first:

| Variable | Overrides |
| --- | --- |
| `CLOOP_ANTHROPIC_API_KEY` | `anthropic.api_key` |
| `CLOOP_ANTHROPIC_BASE_URL` | `anthropic.base_url` |
| `CLOOP_OPENAI_API_KEY` | `openai.api_key` |
| `CLOOP_OPENAI_BASE_URL` | `openai.base_url` |
| `CLOOP_OLLAMA_BASE_URL` | `ollama.base_url` |
| `CLOOP_MODEL` | the model for this run (also read by `cloop mcp`) |

`CLOOP_PROVIDER` appears in both, which is why it works everywhere. The rest of
the `CLOOP_`-prefixed set does not: `cloop providers`, `cloop config show` and
the dashboard will not see a key exported that way. **Prefer the unprefixed
names** unless you specifically need an override scoped to one `cloop run`.

Two more, below the config layer. The `anthropic` and `openai` providers read
`ANTHROPIC_API_KEY` / `OPENAI_API_KEY` themselves when they are constructed
without a key, so those work even on a path that never loaded a config file.
And the `claudecode` provider seeds missing variables — including
`CLAUDE_CODE_OAUTH_TOKEN` — from `~/.openclaw/workspace/.env`, `~/.env` and
`./.env`, without overwriting anything already set in the environment.

Prefer the environment over `.cloop/config.yaml` for credentials in any shared
or hosted setting. For a hub that brokers credentials to sandboxes rather than
holding them in a file, see [the secrets guide](../guides/secrets.md).

---

## Named profiles

A profile is a saved bundle of provider, model, base URL and API key, kept
outside the project in `~/.cloop/profiles.yaml` and managed with
`cloop profile create | use | list | show | delete`. It is overlaid onto the
loaded configuration *before* command-line flags, so `--provider` and `--model`
still win:

```bash
cloop profile create work --provider anthropic --model claude-opus-4-6
cloop profile use work          # make it the active profile
cloop run --profile work        # or override the active one for a single run
```

`--api-key` writes the key in plain text into that file.

---

## Role-based routing

Every task the planner produces carries a role — `backend`, `frontend`,
`testing`, `security`, `devops`, `data`, `docs` or `review`. The router binds a
role to a provider, so one plan can execute across several backends:

```bash
cloop router set backend anthropic
cloop router set docs ollama
cloop router list          # the full table, with unrouted roles showing the default
cloop router clear docs
cloop router clear --all
```

Routes live under `router.routes` in `.cloop/config.yaml`, and roles without a
route use the project's resolved provider. `set` validates both arguments and
accepts `anthropic`, `openai`, `ollama` and `claudecode` — not `mock`. If a
routed provider cannot be built, the run fails at startup naming the role rather
than partway through.

One thing to know before using it: the **model is resolved once for the whole
project**, and every routed provider is called with that same model name. Route
across providers with no model set — letting each fall back to its own default —
rather than pinning a model only one of them understands.

For a run that falls back rather than fans out, `cloop run --fallback
anthropic,openai` tries each named provider in order after the primary fails.

---

**Next:** [The web dashboard](web-ui.md) — running cloop and its projects from a
browser instead of a terminal. See also [core concepts](concepts.md),
[your first project](first-project.md), and the
[command reference](../reference/commands.md).
