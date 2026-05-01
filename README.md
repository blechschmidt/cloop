# cloop — Autonomous AI Feedback Loop

cloop drives AI providers (Claude Code, Anthropic API, OpenAI, Ollama) in a goal-driven autonomous loop. Define a project goal, and cloop iterates until it's done — then optionally keeps improving on its own.

## Install

```bash
go install github.com/blechschmidt/cloop@latest
```

Or build from source:

```bash
git clone https://github.com/blechschmidt/cloop.git
cd cloop
go build -o cloop .
sudo mv cloop /usr/local/bin/
```

### Prerequisites

- Go 1.24+
- At least one provider configured (see [Providers](#providers))

## Quick Start

```bash
mkdir my-project && cd my-project

# Set a goal
cloop init "Build a REST API in Go with SQLite, JWT auth, and user CRUD"

# Let the AI work autonomously
cloop run

# Watch progress
cloop status
cloop log
```

## How It Works

```
┌─────────────┐     ┌─────────────┐     ┌──────────────┐
│  cloop init  │────▶│  cloop run   │────▶│   Provider   │
│  set goal    │     │  feed goal + │     │  execute step│
│              │     │  context     │     │  return output│
└─────────────┘     └──────┬───▲──┘     └──────────────┘
                           │   │
                    step   │   │  result
                    output │   │  + context
                           ▼   │
                    ┌──────────┐
                    │  .cloop/ │
                    │  state   │
                    └──────────┘
```

1. **`cloop init "goal"`** — saves the project goal to `.cloop/state.json`
2. **`cloop run`** — enters a loop: builds a context-aware prompt, calls the AI provider, stores the output, checks for `GOAL_COMPLETE`, repeats until done (or Ctrl+C to pause)
3. **Auto-Evolve** — after `GOAL_COMPLETE`, the AI independently adds features, tests, docs, and improvements

## Providers

cloop supports four AI backends. Switch with `--provider` flag or `cloop config set provider <name>`.

| Provider | Description | Auth |
|----------|-------------|------|
| `claudecode` | Claude Code CLI (default) | `claude auth login` |
| `anthropic` | Anthropic API directly | `ANTHROPIC_API_KEY` |
| `openai` | OpenAI Chat Completions | `OPENAI_API_KEY` |
| `ollama` | Local Ollama server | None (local) |

### Configure providers

```bash
# Show all providers and their status
cloop providers
cloop providers --test   # verify connectivity

# Set the default provider
cloop config set provider anthropic

# Configure Anthropic
cloop config set anthropic.api_key sk-ant-...
cloop config set anthropic.model claude-opus-4-6

# Configure OpenAI
cloop config set openai.api_key sk-...
cloop config set openai.model gpt-4o

# Configure OpenAI-compatible server (e.g., Azure, local)
cloop config set openai.base_url https://my-azure-endpoint.openai.azure.com

# Configure Ollama
cloop config set ollama.base_url http://localhost:11434
cloop config set ollama.model llama3.2

# Configure Claude Code model
cloop config set claudecode.model claude-sonnet-4-6

# Show current config (API keys are masked)
cloop config show
```

### Use a provider for one run

```bash
cloop run --provider anthropic
cloop run --provider openai --model gpt-4o
cloop run --provider ollama --model llama3.2
```

## Commands

### `cloop init [goal]`

Initialize a new project with a goal.

```bash
cloop init "Build a CLI tool that converts CSV to JSON"
cloop init --max-steps 20 "Refactor to clean architecture"
cloop init --model claude-opus-4-6 --instructions "Use Go, no external deps" "Build a web scraper"
cloop init --pm "Build a full REST API"   # Product Manager mode
```

| Flag | Default | Description |
|------|---------|-------------|
| `--max-steps` | `0` (unlimited) | Max autonomous steps |
| `--instructions` | | Additional constraints for the AI |
| `--model` | | Model override |
| `--provider` | | Provider override |
| `--pm` | `false` | Enable Product Manager mode |

### `cloop run`

Start or continue the autonomous loop.

```bash
cloop run
cloop run --provider anthropic
cloop run --auto-evolve
cloop run --model claude-opus-4-6 --step-timeout 15m
cloop run --add-steps 10      # extend max if paused at limit
cloop run --dry-run           # show prompts without executing
cloop run --pm                # enable PM mode for this run
cloop run --pm --plan-only    # decompose goal into tasks, then stop
cloop run --pm --retry-failed # retry previously failed tasks
```

| Flag | Default | Description |
|------|---------|-------------|
| `--provider` | from config | AI provider to use |
| `--model` | from config | Model override |
| `--auto-evolve` | `false` | After goal completion, keep improving |
| `--step-timeout` | `10m` | Timeout per step |
| `--max-tokens` | `0` | Max output tokens per step |
| `--add-steps` | `0` | Add more steps to max before running |
| `--steps` | `0` | Run at most N steps this session (not persisted) |
| `--dry-run` | `false` | Show prompts without running |
| `--pm` | `false` | Product Manager mode |
| `--plan-only` | `false` | PM mode: decompose tasks but don't execute |
| `--retry-failed` | `false` | PM mode: retry failed tasks |
| `--replan` | `false` | PM mode: discard existing plan and re-decompose the goal |
| `--max-failures` | `3` | PM mode: consecutive task failures before stopping |
| `--context-steps` | `3` | Recent steps to include in prompts (0 = none) |
| `--step-delay` | | Delay between steps (e.g. `5s`, `1m`) |
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
cloop log --lines 0    # full output (no truncation)
cloop log --json       # machine-readable JSON array
```

### `cloop export`

Export the session as a markdown report (goal, steps, task plan).

```bash
cloop export                  # print to stdout
cloop export -o report.md     # write to file
```

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

Supported keys: `provider`, `anthropic.api_key`, `anthropic.model`, `anthropic.base_url`, `openai.api_key`, `openai.model`, `openai.base_url`, `ollama.base_url`, `ollama.model`, `claudecode.model`

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

### `cloop reset`

Reset progress but keep the goal and configuration.

### `cloop clean`

Remove `.cloop/` directory entirely.

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

## Auto-Evolve

With `--auto-evolve`, cloop enters a second phase after the goal is complete. The AI independently:

- Adds useful features
- Writes tests
- Improves code quality
- Fixes edge cases
- Adds documentation
- Optimizes performance

Each iteration focuses on **one** improvement. Runs until you press `Ctrl+C`.

```bash
cloop init "Build a monitoring dashboard"
cloop run --auto-evolve
# GOAL_COMPLETE
# Evolve #1: adds sparkline charts
# Evolve #2: adds TCP connection stats
# Evolve #3: adds unit tests
# ... keeps going until Ctrl+C
```

## State

All state is stored in `.cloop/state.json`:

- Goal, instructions, and provider
- Step history with outputs and token counts
- Current step count and status
- PM task plan (when in PM mode)
- Accumulated token usage (`total_input_tokens`, `total_output_tokens`)

Status values: `initialized`, `running`, `complete`, `failed`, `paused`, `evolving`

## Error Handling

- **Provider error (regular mode)** → stops immediately
- **3 consecutive task failures (PM mode)** → stops automatically
- **Ctrl+C** → graceful pause after current step
- **Rate limits / transient errors** → automatic retry with exponential backoff (up to 3 attempts)

## Examples

### Build a project from scratch with Anthropic

```bash
mkdir api && cd api
cloop config set provider anthropic
cloop config set anthropic.api_key $ANTHROPIC_API_KEY
cloop init \
  --instructions "Use Go, chi router, GORM with SQLite, JWT auth" \
  "Build a REST API with users, posts, and comments"
cloop run --auto-evolve
```

### Use PM mode for structured execution

```bash
cd my-project
cloop init --pm "Add comprehensive test coverage and CI pipeline"
cloop run --pm --plan-only   # review the task plan first
cloop run --pm               # execute
```

### Run locally with Ollama (no API costs)

```bash
cloop config set provider ollama
cloop config set ollama.model llama3.2
cloop init "Refactor this Python script to be more readable"
cloop run
```

### One-shot task

```bash
cloop init --max-steps 1 "Add comprehensive unit tests for the auth package"
cloop run
```

## License

MIT
