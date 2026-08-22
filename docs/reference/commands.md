# Command reference

Every `cloop` command and its flags. For conceptual documentation see the
[documentation index](../README.md); for the executor and security
configuration keys see [Configuration](configuration.md).

---

## Commands Reference

### `cloop init [goal]`

Initialize a new project with a goal.

```bash
cloop init "Build a CLI tool that converts CSV to JSON"
cloop init --max-steps 20 "Refactor to clean architecture"
cloop init --model claude-opus-4-6 --instructions "Use Go, no external deps" "Build a web scraper"
cloop init "Build a full REST API"
```

> Every project runs in Product Manager mode: cloop decomposes the goal into a
> visible task plan and works through it. The legacy free-form feedback loop
> (`--pm`/non-PM) was removed in Task 20067 so all changes flow through the task
> pipeline and remain auditable in the UI.

| Flag | Default | Description |
|------|---------|-------------|
| `--max-steps` | `0` (unlimited) | Max autonomous steps |
| `--instructions` | | Additional constraints for the AI |
| `--model` | | Model override |
| `--effort` | | Model reasoning-effort level: `low`, `medium`, `high`, `xhigh`, `max` (claudecode only) |
| `--provider` | | Provider override |

### `cloop run`

Start or continue the autonomous task pipeline.

```bash
cloop run
cloop run --provider anthropic
cloop run --auto-evolve
cloop run --model claude-opus-4-6 --step-timeout 15m
cloop run --add-steps 10      # extend max if paused at limit
cloop run --dry-run           # show prompts without executing
cloop run --plan-only         # decompose goal into tasks, then stop
cloop run --retry-failed      # retry previously failed tasks
cloop run --replan            # discard plan and re-decompose
```

| Flag | Default | Description |
|------|---------|-------------|
| `--provider` | from config | AI provider to use |
| `--model` | from config | Model override |
| `--effort` | from state/config | Model reasoning-effort level: `low`, `medium`, `high`, `xhigh`, `max` (claudecode only) |
| `--auto-evolve` | `false` | After goal completion, keep discovering new tasks |
| `--innovate` | `false` | Innovation mode: push evolve toward novel capabilities |
| `--step-timeout` | `10m` | Timeout per step |
| `--max-tokens` | `0` | Max output tokens per step |
| `--add-steps` | `0` | Add more steps to max before running |
| `--steps` | `0` | Run at most N steps this session (not persisted) |
| `--dry-run` | `false` | Show prompts without running |
| `--plan-only` | `false` | Decompose tasks but don't execute |
| `--retry-failed` | `false` | Retry failed tasks |
| `--replan` | `false` | Discard existing plan and re-decompose |
| `--max-failures` | `3` | PM mode: consecutive task failures before stopping |
| `--context-steps` | `3` | Recent steps to include in prompts (0 = none) |
| `--step-delay` | | Delay between steps (e.g. `5s`, `1m`) |
| `--on-complete` | | Shell command to run on goal completion (e.g. `notify-send done`) |
| `--token-budget` | `0` | Stop when cumulative tokens reach this limit (0 = unlimited) |
| `--notify` | `false` | Send OS desktop notifications on task done, task failed, and session complete |
| `-v, --verbose` | `false` | Show full step output (no truncation) |

**Stopping:** Press `Ctrl+C` to pause gracefully. Run `cloop run` again to resume.

### `cloop status`

Show current project status including provider, progress, and token usage.

```
Goal:     Build a REST API with auth
Status:   complete
Provider: anthropic
Progress: 5/10 steps
Tokens:   12450 in / 3820 out
Created:  2026-05-01 14:00
Updated:  2026-05-01 14:15
```

### `cloop log`

Show step history.

```bash
cloop log              # all steps (truncated output)
cloop log --step 3     # specific step
cloop log --last 5     # show only the 5 most recent steps
cloop log --lines 0    # full output (no truncation)
cloop log --json       # machine-readable JSON array
cloop log --grep "error"  # filter steps containing "error" (case-insensitive)
```

### `cloop goal`

Show or update the project goal without reinitializing (preserves all steps, task plan, and settings).

```bash
cloop goal                        # show current goal
cloop goal "New goal text"        # update the goal in-place
```

### `cloop export`

Export the session as a markdown report (goal, steps, task plan).

```bash
cloop export                  # print to stdout
cloop export -o report.md     # write to file
```

### `cloop report`

Generate a rich progress report with task completion status, timeline, token usage, and cost estimates.

```bash
cloop report                         # terminal report
cloop report --format md             # markdown report to stdout
cloop report --format md -o out.md   # save markdown to file
cloop report --show-outputs          # include step/task output excerpts
```

| Flag | Default | Description |
|------|---------|-------------|
| `--format` | `terminal` | Output format: `terminal`, `md`, `markdown` |
| `--show-outputs` | `false` | Include step/task output excerpts |
| `-o, --output` | | Save report to file instead of stdout |

### `cloop providers [--test]`

List all providers with their configuration status.

```bash
cloop providers         # show all providers + config
cloop providers --test  # also verify connectivity
```

### `cloop config`

Manage project configuration stored in `.cloop/config.yaml`.

```bash
cloop config show                          # show config (keys masked)
cloop config set provider anthropic        # set default provider
cloop config set anthropic.api_key sk-...  # set a value
```

Supported keys: `provider`, `anthropic.api_key`, `anthropic.model`, `anthropic.base_url`, `openai.api_key`, `openai.model`, `openai.base_url`, `ollama.base_url`, `ollama.model`, `claudecode.model`, `webhook.url`, `github.token`, `github.repo`

### `cloop task`

Manage tasks in Product Manager mode.

```bash
cloop task list                    # show all tasks with status
cloop task list --json             # output tasks as JSON array (for scripting)
cloop task show <id>               # show full task details (untruncated)
cloop task show <id> --json        # output task as JSON
cloop task next                    # show the next pending task (preview before running)
cloop task add "Title" --desc "Description" --priority 1
cloop task edit <id> --title "New title" --priority 2
cloop task skip <id>               # mark as skipped
cloop task done <id>               # mark as done
cloop task fail <id>               # mark as failed
cloop task reset <id>              # reset to pending
cloop task remove <id>             # remove from plan
```

### `cloop diff`

Show git changes in the current project.

```bash
cloop diff              # all uncommitted changes vs HEAD
cloop diff --stat       # summary (files changed, insertions, deletions)
cloop diff --name-only  # just the list of changed files
cloop diff --session    # diff from when the cloop session was initialized
```

`--session` is useful for reviewing everything the AI changed during this session.
It finds the last git commit that existed before `cloop init` was run, then diffs from there.

### `cloop watch`

Live-refresh the project status while `cloop run` runs in another terminal.

```bash
cloop watch              # refresh every 2s (default)
cloop watch --interval 5s
```

Shows: goal, status, provider, step/task progress, token counts, and the last step's output — automatically stopping when the session ends.

### `cloop stats`

Show aggregated session statistics.

```bash
cloop stats
```

Includes step timing (total/avg/min/max), token usage, cost estimate for known models, and task breakdown in PM mode.

### `cloop reset`

Reset progress but keep the goal and configuration.

### `cloop clean`

Remove `.cloop/` directory entirely.

---

## Product Manager Mode

PM mode decomposes the goal into a structured task plan, then executes each task one at a time.

```bash
# Initialize with PM mode
cloop init --pm "Build a monitoring dashboard in Go"

# Decompose into tasks first (review before running)
cloop run --pm --plan-only

# Execute the plan
cloop run --pm

# Resume after interruption
cloop run --pm

# Retry any failed tasks
cloop run --pm --retry-failed

# Discard the existing plan and re-decompose
cloop run --pm --replan
```

The AI signals task outcomes with terminal keywords:
- `TASK_DONE` — task completed successfully
- `TASK_SKIPPED` — task not applicable / already done
- `TASK_FAILED` — task could not be completed

Tasks can declare dependencies on other tasks via `depends_on` in the JSON plan.
A task will not start until all its dependencies are `done` or `skipped`.
If a dependency fails, all tasks that depend on it are automatically skipped.

---

## Analysis & Forecasting

### `cloop scope [goal]`

AI-powered project scope analysis before you start. Estimates task count, complexity, risks, prerequisites, and recommends the best execution mode.

```bash
cloop scope "Build a REST API with auth"
cloop scope                           # analyze current project goal
cloop scope --provider anthropic "Add OAuth support"
```

Output: task count estimate, complexity (low/medium/high/very_high), estimated AI invocations, risks, prerequisites, assumptions, and recommended execution mode.

### `cloop forecast`

AI-powered completion forecast with optimistic, expected, and pessimistic scenarios. Renders an ASCII burn-down chart and streams an AI narrative about delivery outlook and acceleration opportunities.

```bash
cloop forecast                       # full forecast (chart + AI narrative)
cloop forecast --quick               # metrics and chart only, no AI
cloop forecast --no-chart            # AI narrative without the chart
cloop forecast --provider anthropic  # use a specific provider
```

| Flag | Default | Description |
|------|---------|-------------|
| `--quick` | `false` | Show metrics and chart only (no AI) |
| `--no-chart` | `false` | Skip the burn-down chart |
| `--provider` | from config | AI provider |
| `--model` | from config | Model override |

### `cloop insights`

AI-powered project health analysis: task velocity, risk score, bottlenecks, role breakdowns, and AI-generated recommendations.

```bash
cloop insights                       # full AI analysis
cloop insights --quick               # metrics panel only, no AI call
cloop insights --provider anthropic
```

| Flag | Default | Description |
|------|---------|-------------|
| `--quick` | `false` | Show metrics only, skip AI analysis |
| `--provider` | from config | AI provider for analysis |
| `--model` | from config | Model override |

### `cloop retro`

AI-powered sprint retrospective: what went well, what went wrong, bottlenecks, velocity notes, key insights, and recommended next actions.

```bash
cloop retro                          # terminal retrospective
cloop retro --format md              # markdown output
cloop retro --format md -o retro.md  # save markdown to file
cloop retro --save-memory            # persist insights to project memory
cloop retro --provider anthropic
```

| Flag | Default | Description |
|------|---------|-------------|
| `--format` | `terminal` | Output format: `terminal` or `md` |
| `-o, --output` | | Write output to file (for `--format md`) |
| `--save-memory` | `false` | Save insights to project memory |
| `--timeout` | `120s` | Analysis timeout |
| `--provider` | from config | Provider to use |
| `--model` | from config | Model override |

### `cloop standup`

Generate an AI-powered daily standup report: what was accomplished, what's planned next, blockers, and delivery forecast. Can post to Slack via webhook.

```bash
cloop standup                          # AI standup (last 24h)
cloop standup --hours 48               # look back 48 hours
cloop standup --quick                  # metrics only, no AI
cloop standup --post                   # post to Slack webhook
cloop standup --save                   # save to .cloop/standup-DATE.md
cloop standup --format slack           # Slack-formatted output
cloop standup --provider anthropic
```

| Flag | Default | Description |
|------|---------|-------------|
| `--hours` | `24` | Reporting window in hours |
| `--quick` | `false` | Show activity summary only, skip AI |
| `--post` | `false` | Post to configured webhook/Slack |
| `--save` | `false` | Save to `.cloop/standup-YYYYMMDD.md` |
| `--format` | `text` | Output format: `text`, `slack` |
| `--provider` | from config | AI provider |
| `--model` | from config | Model override |

To enable Slack posting:
```bash
cloop config set webhook.url https://hooks.slack.com/services/...
```

---

## Planning & Prioritization

### `cloop backlog`

AI-generated prioritized product backlog from your codebase. Surfaces the highest-value improvements ranked by impact-to-effort ratio.

```bash
cloop backlog                          # analyze current project
cloop backlog --format md              # markdown output
cloop backlog --format md -o backlog.md
cloop backlog --as-tasks               # add top items to PM plan
cloop backlog --max-items 10           # limit to top 10 items
cloop backlog --provider anthropic
```

Each item includes:
- **Type**: `feature`, `bug`, `tech_debt`, `performance`, `security`, `docs`
- **Impact**: `high`, `medium`, `low`
- **Effort**: `xs` (<1h), `s` (1-4h), `m` (4-16h), `l` (1-5d), `xl` (>1wk)

| Flag | Default | Description |
|------|---------|-------------|
| `--format` | `terminal` | Output format: `terminal` or `md` |
| `-o, --output` | | Write output to file |
| `--as-tasks` | `false` | Add backlog items to the PM task plan |
| `--max-items` | `0` (all) | Maximum number of items to show/add |
| `--provider` | from config | Provider to use |
| `--model` | from config | Model override |

### `cloop prioritize`

AI-powered smart task reprioritization. Analyzes the current plan and suggests the optimal execution order based on the critical path, dependencies, risk factors, and value delivery.

```bash
cloop prioritize                       # show AI priority suggestions
cloop prioritize --apply               # apply suggestions immediately
cloop prioritize --provider anthropic
```

| Flag | Default | Description |
|------|---------|-------------|
| `--apply` | `false` | Apply suggested priority changes |
| `--dry-run` | `false` | Show suggestions without applying (default) |
| `--provider` | from config | AI provider |
| `--model` | from config | Model override |

### `cloop milestone`

Sprint and release planning. Organize PM tasks into milestones with deadlines and velocity-based forecasting.

```bash
cloop milestone create "v1.0 Launch" --deadline 2026-06-15 --tasks 1,2,3
cloop milestone list                   # show all milestones with progress
cloop milestone show "v1.0 Launch"     # detailed status
cloop milestone assign "v1.0 Launch" --tasks 4,5
cloop milestone plan                   # AI generates milestone structure
cloop milestone forecast               # velocity-based completion forecast
cloop milestone delete "Foundation"
```

**`milestone create`** flags:
| Flag | Description |
|------|-------------|
| `--deadline` | Target deadline in `YYYY-MM-DD` format |
| `--description` | One-sentence milestone description |
| `--tasks` | Comma-separated task IDs to assign (e.g. `1,2,3`) |

**`milestone plan`** flags:
| Flag | Description |
|------|-------------|
| `--force` | Replace existing milestones with AI-generated plan |
| `--provider` | AI provider to use |
| `--model` | Model override |

### `cloop simulate <scenario>`

AI what-if scenario analysis: simulate hypothetical changes before committing. Projects the impact on timeline, risk, and task priorities.

```bash
cloop simulate "what if we cut the authentication module?"
cloop simulate "what if the deadline moves up by 2 weeks?"
cloop simulate "what if we add a second engineer to the project?"
cloop simulate "what if we defer all testing tasks to phase 2?"
cloop simulate "what if we focus only on the critical path?" --apply
cloop simulate "what if we switch from REST to GraphQL?" --provider anthropic
```

Output: summary, timeline delta, risk before/after, confidence, recommendations, task changes, trade-offs, and warnings.

| Flag | Default | Description |
|------|---------|-------------|
| `--apply` | `false` | Apply recommended task changes to the project |
| `--quick` | `false` | Print project snapshot only, no AI call |
| `--provider` | from config | AI provider |
| `--model` | from config | Model override |

---

## Code Quality

### `cloop review [commit-range]`

AI-powered code review for git diffs. Returns a quality score, issues by severity, praise, and suggestions.

```bash
cloop review                           # review all uncommitted changes
cloop review --staged                  # review only staged changes
cloop review --last                    # review the last commit
cloop review HEAD~3..HEAD              # review a range of commits
cloop review --task 3                  # include PM task context in review
cloop review --format md               # markdown output
cloop review --format md -o review.md  # save markdown to file
cloop review --quick                   # diff stats only, no AI call
cloop review --provider anthropic
```

| Flag | Default | Description |
|------|---------|-------------|
| `--staged` | `false` | Review only staged changes |
| `--last` | `false` | Review the last commit |
| `--commit` | | Review a specific commit (hash) |
| `--task` | `0` | Include PM task context in review (task ID) |
| `--format` | `terminal` | Output format: `terminal` or `md` |
| `-o, --output` | | Write output to file |
| `--quick` | `false` | Show diff stats only, no AI call |
| `--timeout` | | Review timeout (e.g. `60s`, `2m`) |
| `--provider` | from config | Provider to use |
| `--model` | from config | Model override |

Issues are graded as: `critical`, `major`, `minor`, `suggestion`.

---

## Collaboration & Automation

### `cloop ask <question>`

Ask the AI anything about your project state, tasks, progress, or blockers. The AI has full context: goal, task plan, recent activity, and project memory.

```bash
cloop ask "What are the remaining blockers?"
cloop ask "Summarize what has been done so far"
cloop ask "Which tasks failed and why?"
cloop ask "What should I do next?"
cloop ask "How long will the remaining tasks take?"
cloop ask --provider anthropic "Are there any risks in the current plan?"
```

| Flag | Default | Description |
|------|---------|-------------|
| `--recent-steps` | `3` | Number of recent steps to include in context (0 = none) |
| `--provider` | from config | Provider to use |
| `--model` | from config | Model override |

### `cloop chat`

Interactive conversational AI product manager. Ask questions, get suggestions, or let the AI update your task plan — all through natural conversation.

```bash
cloop chat
cloop chat --provider anthropic
cloop chat --save         # auto-save transcript on exit
```

**Slash commands inside chat:**

| Command | Description |
|---------|-------------|
| `/status` | Show current project status |
| `/tasks` | List all tasks |
| `/help` | Show available commands |
| `/clear` | Clear conversation history |
| `/save` | Save conversation transcript |
| `/quit` | Exit the chat (also: `/exit`, Ctrl+D) |

The AI can take PM actions on your behalf: mark tasks done, create new tasks, and add notes to project memory.

| Flag | Default | Description |
|------|---------|-------------|
| `--provider` | from config | AI provider |
| `--model` | from config | Model override |
| `--timeout` | `120s` | Response timeout |
| `--save` | `false` | Auto-save transcript on exit |

### `cloop compare [prompt]`

Benchmark the same prompt across multiple AI providers simultaneously. Compare response quality, latency, token counts, and cost side-by-side.

```bash
cloop compare "What is the best way to structure a Go project?"
cloop compare --providers anthropic,openai "Explain REST vs GraphQL"
cloop compare --judge "Write a haiku about software"
cloop compare --task 3           # use a PM task's prompt
cloop compare --format md -o results.md "Design a caching strategy"
cloop compare --full "Summarize microservices best practices"
```

| Flag | Default | Description |
|------|---------|-------------|
| `--providers` | all configured | Comma-separated providers to compare |
| `--judge` | `false` | Use an AI judge to score each response (0-10) |
| `--judge-provider` | first successful | Provider to use as judge |
| `--task` | `0` | Use prompt from PM task #N |
| `--format` | `table` | Output format: `table` or `md` |
| `-o, --output` | | Save output to file |
| `--timeout` | `120` | Per-provider timeout in seconds |
| `--full` | `false` | Show full responses (not truncated) |

### `cloop github`

Sync tasks with GitHub Issues and pull requests.

```bash
cloop github sync                      # import open issues as tasks
cloop github sync --repo owner/repo    # specify repo
cloop github sync --labels bug,enhancement  # filter by label
cloop github sync --dry-run            # preview without saving
cloop github push                      # create issues for unlinked tasks
cloop github push --dry-run            # preview what would be created
cloop github push --done               # also close issues for done tasks
cloop github prs                       # list open PRs with CI status
cloop github prs --state all           # include closed PRs
cloop github link 3 42                 # link task #3 to issue #42
cloop github unlink 3                  # remove task #3's issue link
cloop github status                    # show sync overview
```

Configure GitHub access:
```bash
cloop config set github.token ghp_...         # personal access token
cloop config set github.repo owner/repo       # default repo
```

The repo is auto-detected from the `origin` git remote if not configured. GitHub token is also read from `GITHUB_TOKEN` env var.

### `cloop agent`

Autonomous background agent: executes PM tasks without supervision at a regular interval.

```bash
# Start the agent
cloop agent start                      # every 5 minutes
cloop agent start --interval 2m        # every 2 minutes
cloop agent start --provider anthropic # use Claude API

# Monitor the agent
cloop agent status                     # is it running? what's it doing?
cloop agent logs                       # full log stream
cloop agent logs --tail 30             # last 30 lines
cloop agent follow                     # tail log in real time

# Stop the agent
cloop agent stop

# Maintenance
cloop agent clear-logs                 # truncate the log file
```

The agent executes one PM task per interval, records results, and stores a running state in `.cloop/agent-state.json`. Logs are written to `.cloop/agent.log`.

---

## Project Memory

### `cloop memory`

Manage the project's persistent memory stored in `.cloop/memory.json`. Memory entries are key learnings that are injected into future session prompts.

```bash
cloop memory list                      # list all stored memory entries
cloop memory add "Always use chi router, not net/http"  # add a manual entry
cloop memory delete <id>               # delete a specific entry by ID
cloop memory clear                     # delete all memory entries
```

Memory entries can be created automatically via:
- `cloop retro --save-memory` — saves retro insights to memory
- `cloop chat` — the AI can add notes via natural conversation

### `cloop checkpoint`

Save, restore, or list named snapshots of the project state. Useful before risky changes or experiments.

```bash
cloop checkpoint save before-deploy    # save a named checkpoint
cloop checkpoint save                  # save with auto-generated timestamp name
cloop checkpoint list                  # list all saved checkpoints
cloop checkpoint restore before-deploy # restore (current state auto-backed up)
cloop checkpoint delete before-deploy  # delete a checkpoint
```

Checkpoints are stored as `.json` files in `.cloop/checkpoints/`. Restoring a checkpoint automatically backs up the current state first.

---

## MCP Server (Model Context Protocol)

### `cloop mcp`

Start cloop as an MCP server, exposing it as a set of tools to Claude Desktop, Cursor, Zed, and any other client that supports the [Model Context Protocol](https://spec.modelcontextprotocol.io).

The server speaks JSON-RPC 2.0 over newline-delimited stdio. All log output goes to stderr so it does not corrupt the MCP stream.

```bash
cloop mcp                          # use the configured/auto-detected provider
cloop mcp --provider anthropic     # force a specific provider
cloop mcp --provider openai --model gpt-4o
```

#### Available MCP Tools

| Tool | Description |
|------|-------------|
| `get_status` | Return current orchestrator state: goal, status, step counts, provider |
| `get_plan` | Return the full PM-mode task plan as JSON with all task details |
| `add_task` | Append a new task to the current plan (title, description, priority) |
| `complete_task` | Mark a task done by ID with an optional result summary |
| `run_task` | Execute a one-shot AI prompt using the configured provider |

#### Claude Desktop Configuration

Add to `~/.claude/claude_desktop_config.json` (or the equivalent on your OS):

```json
{
  "mcpServers": {
    "cloop": {
      "command": "cloop",
      "args": ["mcp"],
      "cwd": "/path/to/your/project"
    }
  }
}
```

Once configured, Claude Desktop will offer the cloop tools in any conversation. You can ask Claude to check the plan status, add tasks, or run one-off AI prompts directly through cloop's provider.

#### Cursor Configuration

In `.cursor/mcp.json` at the project root:

```json
{
  "mcpServers": {
    "cloop": {
      "command": "cloop",
      "args": ["mcp"]
    }
  }
}
```

#### Example Session (raw JSON-RPC)

```json
// Client → cloop
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{}}}

// cloop → Client
{"jsonrpc":"2.0","id":1,"result":{"capabilities":{"tools":{}},"protocolVersion":"2024-11-05","serverInfo":{"name":"cloop","version":"1.0.0"}}}

// Client → cloop
{"jsonrpc":"2.0","method":"initialized"}

// Client → cloop
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_plan","arguments":{}}}

// cloop → Client
{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"{ ... plan JSON ... }"}]}}
```

---

## Web Dashboard

### `cloop ui`

Start a local web dashboard with real-time updates via SSE (Server-Sent Events).

```bash
cloop ui                  # start on default port 8080
cloop ui --port 9090      # use a custom port
cloop ui --no-browser     # don't open the browser automatically
```

The dashboard shows: project goal, status, step history with outputs, task list (PM mode), live progress, and run/stop controls.

| Flag | Default | Description |
|------|---------|-------------|
| `--port` | `8080` | Port to listen on |
| `--no-browser` | `false` | Do not open the browser automatically |

### `cloop hub`

Control-plane transport security.

```bash
cloop hub tls-init               # self-signed cert+key for development (0600 key)
cloop hub tls-init --host cloop.example.com --days 90
cloop hub pin                    # SPKI pin of the configured certificate
cloop hub pin --cert /path/to/fullchain.pem
```

`tls-init` refuses to overwrite existing key material without `--force`:
regenerating changes the hub's key, and every agent pinned to the old one stops
connecting until it is re-pinned. See [TLS](#tls) for the serving configuration
and [Remote executors](#remote-executors-edge-devices) for how the pin reaches
a device.

### `cloop hub key`

Sealing-key inspection and online rotation. Stored credentials are sealed under
a per-row data key (DEK); only the DEK is sealed under a key-encryption key
(KEK) derived from `CLOOP_SECRET_KEY`, so rotating rewraps sixty bytes per row
and never decrypts a payload.

```bash
cloop hub key status                       # which key seals what, and rotation progress
cloop hub key list                         # keys, and whether each is still openable
cloop hub key rotate --dry-run             # count what would move, write nothing
cloop hub key rotate                       # mint a new KEK and rewrap onto it
cloop hub key rotate --continue            # resume onto the current primary
cloop hub key retire <key-id> --yes        # destroy an old key's salt (irreversible)
```

| Flag | Applies to | Default | Description |
|------|-----------|---------|-------------|
| `--workdir` | all | current directory | Hub directory holding `.cloop/state.db` |
| `--json` | `list`, `status`, `rotate` | `false` | Machine-readable output |
| `--dry-run` | `rotate` | `false` | Report what would be rewrapped without writing |
| `--continue` | `rotate` | `false` | Resume onto the current primary instead of minting a new key |
| `--batch` | `rotate` | `128` | Rows read per round |
| `--yes` | `retire` | `false` | Confirm irreversible destruction of the key's salt |

Rotation is safe to interrupt and safe to run against a serving hub; `retire` is
a deliberate second step and refuses while any row still references the key. The
full procedure, including upgrading a hub that predates envelope encryption, is
in the [runbook](../operations/runbook.md#key-rotation).

These subcommands write to the state database directly rather than through the
HTTP API, so they require filesystem access to it — the same root-shell caveat
as `cloop hub token`.

---

## Network egress

`cloop egress grant / list / test / revoke` issue and inspect the leases that
let an isolated sandbox reach the outside world through the control plane's
proxy — see [the secrets guide](../guides/secrets.md#egress-leases). The
subcommand below is about the other enforcement point.

### `cloop egress firewall`

Render the packet filter an egress authorisation compiles to, or ask what it
would do to one address.

The two enforcement points answer different questions and an operator has to be
able to see both. `cloop egress test` asks the *proxy* "may I connect to this
URL", which is the layer-7 answer and depends on the workload choosing to use
the proxy. This asks the *packet filter* "would this packet leave", which is the
answer that binds a workload that does not.

The rendered output is the same text the driver installs, so it can be diffed
against `nft list table inet cloop_sbx_<id>` on a host or
`kubectl get netpol -o yaml` in a cluster. Nothing here touches the host: it
compiles and prints.

| Flag | Default | Description |
|------|---------|-------------|
| `--grant` | | Compile a stored grant by ID instead of using the flags below |
| `--cidrs` | | Address ranges the sandbox may reach directly |
| `--ports` | | Destination ports; required whenever a destination is allowed |
| `--internet` | `false` | Allow every public address on `--ports` |
| `--broker` | | Egress proxy endpoint the sandbox may reach (`address:port`) |
| `--resolver` | | DNS server it may query directly (address, or `address:port`) |
| `--format` | `rules` | `rules`, `nft`, `nft-bridge` or `networkpolicy` |
| `--table` | `cloop_sbx_preview` | nft table / NetworkPolicy name |
| `--bridge` | | Host interface to filter; required by `--format nft-bridge` |
| `--check` | | Report the verdict for one `address:port` and exit 1 if dropped |

`--format nft` renders the in-namespace form (output, input and forward chains,
all defaulting to drop); `nft-bridge` renders the host-side form that filters
one bridge. `--check` accepts an optional `/tcp` or `/udp` suffix and defaults
to TCP.

**Previewing a configuration before writing it.** The rules are printed in
evaluation order, first match wins, with the reason that will appear in the
ruleset and in the audit trail:

```console
$ cloop egress firewall --cidrs 10.8.0.0/24 --ports 6443 --format rules
IP-layer egress filter  mode filtered, 22 rules, from flags

  allow  127.0.0.0/8                any          sandbox-local loopback [namespace-local]
  allow  ::1/128                    any          sandbox-local loopback [namespace-local]
  allow  10.8.0.0/24            tcp 6443         granted CIDR (waives private (RFC1918/ULA))
  drop   169.254.169.254/32         any          cloud metadata service (169.254.169.254)
  drop   0.0.0.0/32                 any          unspecified address
  drop   127.0.0.0/8                any          loopback
  drop   224.0.0.0/4                any          multicast
  drop   169.254.0.0/16             any          link-local
  drop   10.0.0.0/8                 any          private (RFC1918/ULA)
  drop   172.16.0.0/12              any          private (RFC1918/ULA)
  drop   192.168.0.0/16             any          private (RFC1918/ULA)
  drop   100.64.0.0/10              any          carrier-grade NAT (RFC6598)
  drop   ::/128                     any          unspecified address
  drop   ::1/128                    any          loopback
  drop   ff00::/8                   any          multicast
  drop   fe80::/10                  any          link-local
  drop   fc00::/7                   any          private (RFC1918/ULA)
  drop   64:ff9b::/96               any          NAT64 translation prefix
  drop   64:ff9b:1::/48             any          NAT64 translation prefix (RFC 8215)
  drop   ::ffff:0:0:0/96            any          IPv4-translatable prefix
  drop   2002::/16                  any          6to4 translation prefix
  drop   ::/96                      any          IPv4-compatible prefix (deprecated)
  drop   everything else                         default deny
```

The granted `10.8.0.0/24` is allowed *before* `10.0.0.0/8` is dropped: that
ordering is the waiver rule, and it is why the grant buys that prefix on that
port and nothing else. The last five drops are the IPv6 encodings that carry an
IPv4 address; a packet filter cannot unwrap one, so it drops the prefix whole.

**Seeing what a hostname allowlist became.** The warning is the point of the
command, not decoration — it appears in every format, including the nft
comments:

```console
$ cloop egress firewall --internet --ports 443 --format rules
IP-layer egress filter  mode filtered, 23 rules, from flags

warning: every public address is reachable on port 443; only the private, loopback, link-local, CGNAT and metadata ranges are filtered

warning: no resolver is allowed, so DNS will fail: name lookups leave the sandbox on UDP/53 and this policy drops them. Pass the sandbox's resolvers, or use the broker, which resolves on its behalf.
```

With `--grant <id>`, a grant whose allowlist is hostnames produces a warning
naming those hostnames and the port they widened to, because that is the single
most useful thing this command reports.

**Asking about one address — `--check`.** The verdict is on stdout and *also*
in the exit status: **0** when the packet would leave, **1** when it would be
dropped. An operator automating "is this sandbox still confined" should not
have to parse prose.

```console
$ cloop egress firewall --internet --ports 443 --check 169.254.169.254:80
DROP  169.254.169.254 169.254.169.254:80/tcp — cloud metadata service (169.254.169.254)
$ echo $?
1

$ cloop egress firewall --cidrs 10.8.0.0/24 --ports 6443 --check 10.8.0.5:6443
ALLOW 10.8.0.5 10.8.0.5:6443/tcp — granted CIDR (waives private (RFC1918/ULA))
$ echo $?
0

$ cloop egress firewall --cidrs 10.8.0.0/24 --ports 6443 --check 10.8.0.5:22
DROP  10.8.0.5 10.8.0.5:22/tcp — private (RFC1918/ULA)
$ echo $?
1
```

The third is the useful one: the address is inside the granted range, and it is
dropped anyway, because the waiver covers the prefix *on its ports*. The reason
names the rule that decided, so "why can my sandbox not reach this" has an
answer rather than a guess.

**Rendering what a host would run.** `nft-bridge` is the form the container
driver installs, and both hooks carry the same rules — `forward` for
destinations the host routes onward, `input` for destinations that belong to
the host itself:

```console
$ cloop egress firewall --cidrs 10.8.0.0/24 --ports 6443 --resolver 10.88.0.1 \
    --format nft-bridge --bridge br-8e9671342cdf --table cloop_sbx_container
# cloop sandbox egress filter — mode filtered
# Generated by pkg/netfilter. Edits are lost on the next task.

add table inet cloop_sbx_container
delete table inet cloop_sbx_container
table inet cloop_sbx_container {
	chain forward {
		type filter hook forward priority 0; policy accept;
		iifname != "br-8e9671342cdf" return comment "not this sandbox"
		ct state established,related counter accept
		ct state invalid counter drop
		ip daddr 10.8.0.0/24 tcp dport 6443 counter accept comment "granted CIDR (waives private (RFC1918/ULA))"
		ip daddr 10.88.0.1/32 udp dport 53 counter accept comment "DNS resolver"
		ip daddr 10.88.0.1/32 tcp dport 53 counter accept comment "DNS resolver (truncated answers retry over TCP)"
		ip daddr 169.254.169.254/32 counter drop comment "cloud metadata service (169.254.169.254)"
		…
		counter drop comment "default deny"
	}

	chain input {
		type filter hook input priority 0; policy accept;
		…
	}
}
```

The chain policy is `accept` and the drop is explicit, because base chains on
the same hook all run: a `policy drop` here would take down every other
container on the host. Each chain returns immediately for traffic that is not
from this sandbox's bridge. The `add table` / `delete table` / `table` preamble
makes a re-apply replace rather than accumulate — `add` is a no-op on an
existing table, which is what makes the `delete` safe on a first run — and
`nft -f` commits the whole thing as one transaction. Every rule carries a
`counter`, which is what makes
`nft list table inet …` useful when a sandbox cannot reach something — see the
[runbook](../operations/runbook.md#incident-playbooks).

Full context: [IP-layer egress filtering](configuration.md#ip-layer-egress-filtering)
for the config keys, and [the security model](../security/model.md#the-network-the-sandbox-sits-on)
for what each layer does and does not bind.

---

## Executor internals

Commands an executor runs on your behalf. They are documented because you will
meet them in a container log or a failing init container, not because you are
expected to type them.

### `cloop workspace provision`

Materialise a git workspace into a directory, then exit. This is what an
isolated executor runs *before* the harness starts: a Kubernetes init container
named `workspace`, or any other place that has to hold the code before the
workload does. The Kubernetes driver builds the argv, so the flags below are a
wire format between the driver and this command rather than a UI.

> Unrelated to the other `cloop workspace` subcommands (`add`, `list`,
> `switch`, …), which manage multiple cloop projects from one root. Same noun,
> different feature.

```bash
cloop workspace provision --dir /workspace/project --repo https://github.com/acme/app.git
cloop workspace provision --dir /workspace/project --repo https://github.com/acme/app.git \
    --ref main --depth 1 --size-limit-mb 512
```

| Flag | Default | Description |
|------|---------|-------------|
| `--dir` | | Absolute directory to provision the source tree into (**required**) |
| `--repo` | | `https://` clone URL of the repository to fetch (**required**) |
| `--ref` | the remote's default branch | Branch, tag or commit to check out |
| `--depth` | `0` | Shallow-fetch depth; `0` fetches full history |
| `--size-limit-mb` | `0` | Refuse a provisioned tree larger than this many megabytes; `0` means no limit |

`--dir` must be absolute: a relative path would resolve against whatever working
directory the process happens to have, which inside a Pod is the image author's
choice rather than the driver's. The repo URL must be `https://` and must not
embed credentials — see [the workspace contract](../architecture/executors.md#workspace-provisioning)
for why.

**Credentials come from the environment**, because that is the only channel a
Pod has that is neither an argv (`/proc` publishes those to every process under
the same uid) nor a file (which outlives the process that needed it):

| Variable | Meaning |
|----------|---------|
| `CLOOP_WORKSPACE_TOKEN` | the bare token; absent or empty means an unauthenticated fetch, which works for a public repository |
| `CLOOP_WORKSPACE_USER` | the basic-auth username; defaults to `x-access-token`, which is what GitHub expects alongside a PAT |

Both are read and **removed from the process's environment before anything is
spawned**, and no output of this command can contain either — every byte it
writes and every error it returns is passed through the same redaction the
provisioner applies.

The sequence is `git init`, `remote add origin`, `fetch`, then
`checkout --detach FETCH_HEAD` — not `git clone`, because `clone` cannot name a
bare commit SHA. A directory that already holds a checkout of the *same* remote
is fetched into rather than re-cloned; one holding a *different* remote is a
refusal naming both URLs, since re-cloning would discard whatever is there.

Running it by hand is the way to reproduce a workspace failure outside a
cluster:

```bash
CLOOP_WORKSPACE_TOKEN=ghp_… cloop workspace provision \
    --dir /tmp/repro --repo https://github.com/acme/app.git --ref main
```

A non-zero exit means the tree is not there. The message names the machine, the
repository and the directory, and is safe to paste into a bug report.

