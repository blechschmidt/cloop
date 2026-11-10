# Choosing and configuring a provider

A **provider** is what cloop uses when it needs a model: a local CLI, a hosted
API, or a server on your own machine. The plan, the tasks and the executors work
the same whichever provider you pick, and you can switch to another one later
with a single command.

- [The backends](#the-backends)
- [Setting one up](#setting-one-up)
- [Checking what is configured](#checking-what-is-configured)
- [How a provider is chosen](#how-a-provider-is-chosen)
- [How a model is chosen](#how-a-model-is-chosen)
- [Reasoning effort](#reasoning-effort)
- [GitHub Copilot](#github-copilot)
- [Environment variables](#environment-variables)
- [Named profiles](#named-profiles)
- [Role-based routing](#role-based-routing)

---

## The backends

| Name | Talks to | Credential | Default model |
| --- | --- | --- | --- |
| `claudecode` | the `claude` CLI as a subprocess | whatever the CLI is already signed in with | none (the CLI decides) |
| `copilot` | the GitHub Copilot CLI (`copilot`) as a subprocess | whatever the CLI is already signed in with | none (the CLI decides) |
| `anthropic` | `https://api.anthropic.com/v1` | `ANTHROPIC_API_KEY` | `claude-opus-4-6` |
| `openai` | `https://api.openai.com/v1` (Chat Completions) | `OPENAI_API_KEY` | `gpt-4o` |
| `ollama` | `http://localhost:11434` | none | `llama3.2` |

**`claudecode`** is the default. Like `copilot`, it holds no credential of its
own. It runs the `claude` binary once per call and uses the sign-in that CLI
already has, so you pay through a Claude Code subscription instead of metered
API billing. cloop looks for `claude` on `PATH` first, then at
`~/.local/bin/claude`, `~/.npm-global/bin/claude` and `/usr/local/bin/claude`,
so it also works when the dashboard is started by a service manager with a
minimal environment. `claudecode` has no default model. cloop passes `--model`
only when one is set, and otherwise the CLI chooses. On a single-user install
the sign-in is the machine's. On a hub with SSO it is the sign-in of the user
who made the request, because each identity has its own Claude login (see
[per-user Claude Code logins](../security/claude-code-identity.md)).

**`copilot`** works the same way with GitHub Copilot. It runs the
[GitHub Copilot CLI](#github-copilot) once per call, as an agent with its own
tools in the project directory, using the sign-in that CLI already has. You pay
through a Copilot seat instead of per token.

**`anthropic`** gives you the same family of models as `claudecode` over the
HTTP API, billed per token. Pick it when you want to use an API key instead of a
subscription. **`openai`** uses the Chat Completions API. Set `openai.base_url`
to use any other server that implements the same endpoint, such as Azure
OpenAI, a llama.cpp server or a gateway. This is the supported way to use
OpenAI-compatible backends. **`ollama`** needs no key and talks to a server on
your own machine, so nothing leaves it.

There is also a **`mock`** provider, accepted by `cloop config set provider` and
by `cloop run --mock`. It answers from `.cloop/mock_responses.yaml` (or
`mock.responses_file`) and by default returns `TASK_DONE`. It makes no calls and
costs nothing. Use it to test the shape of a plan or a CI pipeline, and for
nothing else.

---

## Setting one up

Configuration lives in `.cloop/config.yaml`. cloop writes the file with mode
`0600` because it may contain an API key. Use `cloop config set` to change it:
it checks each value before saving and rejects unknown keys.

```bash
cloop config set provider anthropic
cloop config set anthropic.api_key sk-ant-...
cloop config set anthropic.model claude-opus-4-6
```

These are all the provider keys that `cloop config set` accepts:

| Key | Notes |
| --- | --- |
| `provider` | one of `anthropic`, `openai`, `ollama`, `claudecode`, `copilot`, `mock`. Anything else is rejected |
| `anthropic.api_key` / `.model` / `.base_url` | |
| `openai.api_key` / `.model` / `.base_url` | `base_url` is how you reach an OpenAI-compatible server |
| `ollama.base_url` / `.model` | |
| `claudecode.model` | |
| `claudecode.effort` | `low`, `medium`, `high`, `xhigh`, `max` (see [Reasoning effort](#reasoning-effort)) |
| `copilot.model` | `auto` lets Copilot pick per request |
| `copilot.effort` | the same values as `claudecode.effort` |
| `mock.responses_file` / `mock.default` | |

Some provider settings have no `cloop config set` key, so you edit them in
`.cloop/config.yaml` directly:

- the inference parameters: `temperature`, `top_p`, `max_tokens`, and
  `frequency_penalty` for OpenAI. The `anthropic` provider leaves out
  `temperature` and `top_p` for the Claude models that refuse them: every Fable
  model, Claude Opus 4.7 and later, Claude Sonnet 5 and later, and Claude
  Haiku 5.5.
- the Claude Code subscription caps: `claudecode.max_weekly_pct`,
  `max_five_hour_pct`, `max_weekly_opus_pct` and `max_weekly_sonnet_pct`. You
  can also edit these in the dashboard. A run stopped by a cap resumes by itself
  when the window reopens (see
  [Resuming a capped run](../reference/configuration.md#resuming-a-capped-run)).
- [`claudecode.background.*`](../reference/configuration.md#background-work-left-by-an-agent)
  and the matching `copilot.background.*`

`cloop config show` prints the configuration in effect, with API keys masked.
Every save is also copied into `.cloop/state.db`. If the two drift apart,
`cloop config diff` compares them and `cloop config sync` reconciles them.

---

## Checking what is configured

```bash
cloop providers          # what is registered, what is configured, what is default
cloop providers --test   # ...and does it actually answer
```

The listing marks the default with `*` and shows each backend's endpoint and
resolved model. "Configured" only means that a credential is present.
`claudecode` and `ollama` always show as configured because neither needs one,
and `copilot` shows as configured when its CLI is installed. To find out whether
a provider works, add `--test`. It creates each provider and asks it to reply
`OK`, with a 30-second timeout. A missing `claude` binary, a `copilot` that
isn't signed in or an unreachable Ollama shows up as `FAIL` with the underlying
error.

`cloop providers` reads the configuration through the same loader as every
other command, and that loader only applies the unprefixed environment
variables. A key exported as `CLOOP_ANTHROPIC_API_KEY` is used by `cloop run`
but doesn't show up here. See [Environment variables](#environment-variables).

---

## How a provider is chosen

`cloop run` uses the first of these that is set:

1. **`--provider`** on the command line (`--mock` is shorthand for
   `--provider mock`).
2. **`provider:` in `.cloop/config.yaml`**, after `CLOOP_PROVIDER` and any
   `--profile` overlay have been applied to it.
3. **The provider saved in project state**, set by `cloop init --provider` or
   by the dashboard's Provider picker.
4. **Auto-detection**: `ANTHROPIC_API_KEY` or `CLOOP_ANTHROPIC_API_KEY` selects
   `anthropic`. Otherwise `OPENAI_API_KEY` or `CLOOP_OPENAI_API_KEY` selects
   `openai`. If neither is set, cloop uses `claudecode`.

In practice step 2 almost always decides. When `.cloop/config.yaml` doesn't
exist, the loader returns the built-in defaults, which already contain
`provider: claudecode`. Steps 3 and 4 are only reached when the file exists and
its `provider:` key is empty. If you want the provider saved in project state to
be used, leave that key blank.

At the start of the run cloop saves the chosen provider in project state, so the
next `cloop run` without flags uses the same one.

---

## How a model is chosen

cloop chooses the model separately from the provider. It uses the first of these
that is set:

| | Source |
| --- | --- |
| 1 | `--model` on the command line |
| 2 | `CLOOP_MODEL` in the environment |
| 3 | the per-provider key: `anthropic.model`, `openai.model`, `ollama.model`, `claudecode.model`, `copilot.model` |
| 4 | the model saved in project state (`cloop init --model`, or the dashboard's picker) |
| 5 | the provider's own default |

The provider's own default is `claude-opus-4-6` for `anthropic`, `gpt-4o` for
`openai` and `llama3.2` for `ollama`. `claudecode` and `copilot` have none. If
no model is set, cloop passes no `--model` to the CLI, and the CLI uses its own
default.

For `claudecode` and `anthropic`, the dashboard's model pickers and
`cloop init --interactive` offer every Claude model Anthropic serves: Claude
Fable 5.2, 5.1 and 5, Claude Opus 5.5, 5, 4.8, 4.7, 4.6 and 4.5, Claude Sonnet
5.5, 5, 4.6 and 4.5, and Claude Haiku 5.5 and 4.5. Their IDs follow one
pattern, for example `claude-fable-5-2`, `claude-opus-5-5` and
`claude-haiku-4-5`. Any other model ID works too: pass it with `--model` or
`cloop config set`, or type it in the wizard. Claude Mythos is not offered
because Anthropic serves it only to organizations in its verification programs.

cloop only reads the per-provider key of the provider in use. Setting
`openai.model` changes nothing while the project runs on `anthropic`, so you can
keep all of them configured at once.

---

## Reasoning effort

`claudecode` and `copilot` accept a reasoning-effort level and pass it to the
CLI unchanged: as `--effort` to `claude`, and as `--reasoning-effort` to
`copilot`. Valid values are `low`, `medium`, `high`, `xhigh` and `max`. If no
level is set, the CLI uses its default.

```bash
cloop run --effort high
cloop config set claudecode.effort high     # the project-wide default
cloop init --effort high "…"                # saved into project state
```

`--effort` takes precedence over `claudecode.effort` (or `copilot.effort`) in
the config, which takes precedence over the effort saved in project state. An
invalid `--effort` is an error. An invalid value in the file is reported on
stderr and ignored, so a bad value in the YAML can't make every CLI call fail.

The other backends ignore this setting. OpenAI's o-series models do get a
`reasoning_effort`, but cloop derives it from its extended-thinking budget, not
from `--effort`, and only for models whose name begins with `o1`, `o3` or
`o4-mini`.

With `--think`, the `anthropic` provider asks Claude Opus 4.6, Claude Sonnet 4.6
and every later Claude model for adaptive thinking, where the model decides how
much to think. Only older models accept a fixed budget, so `--think-budget` is
sent to them alone. The Fable models and Claude Opus 5.5 think on every call,
with or without `--think`.

---

## GitHub Copilot

The `copilot` provider runs the [GitHub Copilot
CLI](https://docs.github.com/copilot/how-tos/copilot-cli). Like `claude`, it is
an agent harness: it edits files, runs commands and searches the project
itself. Install it and sign in once, as the user that cloop runs as:

```bash
npm install -g @github/copilot          # or: curl -fsSL https://gh.io/copilot-install | bash
copilot login                           # or export COPILOT_GITHUB_TOKEN=github_pat_…
cloop config set provider copilot
cloop providers --test                  # copilot … OK
```

cloop looks for `copilot` on `PATH`, then at `~/.local/bin/copilot` (where the
install script puts it when run as a normal user), `~/.npm-global/bin/copilot`,
`/usr/local/bin/copilot` and `/opt/homebrew/bin/copilot`.

**Signing in.** cloop keeps no Copilot credential of its own, and on a hub
without single sign-on it adds none to a run on its host. The CLI uses the first
of these it finds: `COPILOT_GITHUB_TOKEN`, `GH_TOKEN`, `GITHUB_TOKEN`, the
account stored by `copilot login`, and the GitHub CLI's account. On a hub with
single sign-on, each person's runs sign in with their own credential instead
(see below).

A token must act for a person with a Copilot seat. Use a fine-grained personal
access token with the *Copilot Requests* permission, or an OAuth token. Classic
`ghp_` tokens are not accepted. If the environment may also contain a GitHub
token for something else, export `COPILOT_GITHUB_TOKEN` instead of `GH_TOKEN`,
because the CLI reads it first. With `COPILOT_PROVIDER_BASE_URL` set, the CLI
uses a model provider of your own and needs no GitHub sign-in. This is "bring
your own key", and it works with OpenAI-compatible, Azure or Anthropic
endpoints, including Ollama. See `copilot help providers`.

**How cloop runs it.** cloop starts the CLI once per call in prompt mode, with
the prompt on stdin and `--silent`, so it reads only the agent's answer,
including the `TASK_DONE` / `TASK_FAILED` / `TASK_SKIPPED` signal. Every tool is
allowed (`--allow-all-tools --allow-all-paths --allow-all-urls`), in the same
way that `claudecode` runs with `bypassPermissions`, because nobody is there to
approve tool use. `--no-ask-user` stops the agent from pausing to ask questions.
`COPILOT_AUTO_UPDATE` is `false` unless your environment sets it, so a run uses
the CLI version that was installed.

The model and effort are passed as `--model` and `--reasoning-effort`. Each
conversation gets an ID (`--session-id`), so when an agent ends its turn before
the task is finished, cloop hands the task back to it in the same conversation
(`--resume`), as with `claudecode`. Token usage comes from the CLI's own usage
report and is recorded like any other provider's, with the model `auto`
replaced by the model Copilot chose. The review gate's reviewer runs with only
the reading tools (`view`, `grep`, `glob`), no built-in MCP servers, and the
CLI's path and URL checks left on. Background work the agent leaves running is
waited for in the same way as for `claudecode`, under `copilot.background` (see
[Background work left by an
agent](../reference/configuration.md#background-work-left-by-an-agent)).

**Models.** Which models you can use depends on your Copilot plan. To list them,
start `copilot` and type `/model`. The dashboard's picker suggests `auto`,
`claude-sonnet-4.5`, `claude-opus-4.5`, `claude-haiku-4.5`, `gpt-5.4` and
`gpt-5-mini`, and it also keeps a model saved on the project that isn't in that
list. If your plan doesn't offer the model, the call fails with the CLI's own
error.

**In a sandbox.** A `copilot` project bound to an executor that isolates it from
the hub needs the CLI installed where the task runs, and a credential granted to
the project.

- **In a container** (a container executor, a device in container mode, or a
  virtual executor), use `ghcr.io/blechschmidt/cloop-harness-copilot`, the
  published harness image with the Copilot CLI added. It is a separate variant
  because the CLI nearly doubles the image size (+445 MB unpacked, +217 MB
  pulled; see [the published
  images](../reference/sandbox.md#the-published-images-and-what-an-image-carries)).
  The default `cloop-harness` image contains only `claude`, and its
  `org.cloop.harnesses` label says so. If a `copilot` project uses it, the hub
  refuses the run before it starts (409 `sandbox_image_lacks_harness`) and the
  error names the variant.
- **On a device's own host**, the device installs the CLI the first time a task
  sent to it needs one, as it does for `claude`. It uses GitHub's documented
  installer (`https://gh.io/copilot-install`) and installs into the agent user's
  `~/.local/bin`. If
  [`executors.auto_install_harness`](../reference/configuration.md#automatic-harness-installation)
  is off, the task is refused instead, and the error lists the ways to fix it.
  An agent built before this release has no installer for `copilot` and reports
  that. Upgrade the agent, or install the CLI on the device yourself. A device
  advertises `copilot` when the CLI is on the agent's `PATH`.

The credential is `COPILOT_GITHUB_TOKEN`, or `COPILOT_PROVIDER_BASE_URL` if the
project uses its own model provider. Without one, the hub refuses to start the
task. The *Copilot credential* card on the Overview grants one in a single step
(see [the credential of a sandboxed
run](../guides/secrets.md#the-claude-credential-of-a-sandboxed-run)). The CLI
keeps its token out of the environment of the commands the agent runs.

**On a hub with single sign-on, each person uses their own credential.** This
covers a `copilot` run on the hub's own host, the dashboard's model calls on a
`copilot` project (Split, Revise, the blocker analysis, the plan assistant, the
replays), and every resume or failover of a run. Each of these acts for a
person, and the hub signs the CLI in with a credential granted to the project
for that person. That is either their own token, pasted into the project's
*Copilot credential* card and stored as their personal secret, or one that an
administrator shared with the project. The CLI never uses the host's `copilot
login`, `GH_TOKEN` or `GITHUB_TOKEN`: the hub strips every `COPILOT_*`
variable, `GH_TOKEN`, `GITHUB_TOKEN` and `GH_HOST` from the environment the CLI
inherits, and gives each person their own Copilot home for its sessions and
logs. Someone without a credential is refused and shown the dialog that grants
one, and a run the hub would continue for them is paused instead. See
[per-person Copilot credentials](../security/copilot-identity.md).

**What does not apply.** The Claude Code usage caps and the model relay only
apply to Claude. A `copilot` run is not paused by `claudecode.max_*_pct`, and
its model calls go directly to GitHub (or to your own provider). The hub's own
host doesn't keep people apart: a run there uses the hub's own user account, and
its agent can read anything that account can. To keep people's agents apart,
bind `copilot` projects to an isolating executor, where the same personal grant
signs the sandbox in.

---

## Environment variables

There are two sets of variables, and they behave differently. The configuration
loader applies the first set, so these affect every command:

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

Only `cloop run` applies the second set, on top of the first:

| Variable | Overrides |
| --- | --- |
| `CLOOP_ANTHROPIC_API_KEY` | `anthropic.api_key` |
| `CLOOP_ANTHROPIC_BASE_URL` | `anthropic.base_url` |
| `CLOOP_OPENAI_API_KEY` | `openai.api_key` |
| `CLOOP_OPENAI_BASE_URL` | `openai.base_url` |
| `CLOOP_OLLAMA_BASE_URL` | `ollama.base_url` |
| `CLOOP_MODEL` | the model for this run (also read by `cloop mcp`) |

Both the loader and `cloop run` apply `CLOOP_PROVIDER`, which is why it works
everywhere. The other `CLOOP_`-prefixed variables don't: `cloop providers`,
`cloop config show` and the dashboard won't see a key exported that way. Use the
unprefixed names unless you need an override for a single `cloop run`.

Two more sources sit below the config layer. The `anthropic` and `openai`
providers read `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` themselves when they are
created without a key, so those variables work even where no config file was
loaded. The `claudecode` provider fills in missing variables, including
`CLAUDE_CODE_OAUTH_TOKEN`, from `~/.openclaw/workspace/.env`, `~/.env` and
`./.env`. It never overwrites a variable that is already set.

On shared or hosted machines, keep credentials in the environment instead of in
`.cloop/config.yaml`. To have a hub broker credentials to sandboxes instead of
keeping them in a file, see [the secrets guide](../guides/secrets.md).

---

## Named profiles

A profile is a saved set of provider, model, base URL and API key. Profiles are
kept outside the project in `~/.cloop/profiles.yaml`, and you manage them with
`cloop profile create | use | list | show | delete`. cloop applies a profile to
the loaded configuration before the command-line flags, so `--provider` and
`--model` still take precedence:

```bash
cloop profile create work --provider anthropic --model claude-opus-4-6
cloop profile use work          # make it the active profile
cloop run --profile work        # or override the active one for a single run
```

`--api-key` stores the key in that file as plain text.

---

## Role-based routing

Every task the planner creates has a role: `backend`, `frontend`, `testing`,
`security`, `devops`, `data`, `docs` or `review`. The router assigns a provider
to a role, so the tasks of one plan can run on several backends:

```bash
cloop router set backend anthropic
cloop router set docs ollama
cloop router list          # the full table, with unrouted roles showing the default
cloop router clear docs
cloop router clear --all
```

Routes are stored under `router.routes` in `.cloop/config.yaml`. Roles without
a route use the project's provider. `set` checks both arguments and accepts
`anthropic`, `openai`, `ollama`, `claudecode` and `copilot`, but not `mock`. If
a routed provider can't be created, the run fails at startup with an error that
names the role, so it doesn't fail partway through.

The model is chosen once for the whole project, and every routed provider is
called with that same model name. So when you route across providers, leave the
model unset and let each provider use its own default. Don't set a model that
only one of them understands.

To fall back to other providers instead of splitting the work between them, use
`cloop run --fallback anthropic,openai`. It tries each named provider in turn
after the primary one fails.

---

**Next:** [The web dashboard](web-ui.md) shows how to run cloop and its projects
from a browser instead of a terminal. See also [core concepts](concepts.md),
[your first project](first-project.md) and the
[command reference](../reference/commands.md).
