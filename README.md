# cloop — Autonomous Feedback Loop for Claude Code

cloop wraps [Claude Code](https://docs.anthropic.com/en/docs/claude-code) in a goal-driven feedback loop. Define a project goal, and cloop will autonomously drive Claude Code through multiple iterations until the goal is complete — then optionally keep improving the project on its own.

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

- [Claude Code](https://docs.anthropic.com/en/docs/claude-code) installed and authenticated (`claude auth login`)
- Go 1.24+

## Quick Start

```bash
mkdir my-project && cd my-project

# Set a goal
cloop init "Build a REST API in Go with SQLite, JWT auth, and user CRUD"

# Let Claude work autonomously
cloop run --dangerously-skip-permissions

# Watch progress
cloop status
cloop log
```

## How It Works

```
┌─────────────┐     ┌─────────────┐     ┌──────────────┐
│  cloop init  │────▶│  cloop run   │────▶│  Claude Code  │
│  set goal    │     │  feed goal + │     │  execute step │
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
2. **`cloop run`** — enters a loop:
   - Builds a prompt with the goal, instructions, and recent step history
   - Pipes it to `claude --print` via stdin
   - Stores the output, checks for `GOAL_COMPLETE`
   - Repeats until done (or Ctrl+C to pause)
3. **Auto-Evolve** — after `GOAL_COMPLETE`, Claude independently adds features, tests, docs, and improvements

## Commands

### `cloop init [goal]`

Initialize a new project with a goal.

```bash
cloop init "Build a CLI tool that converts CSV to JSON"
cloop init --max-steps 20 "Refactor to clean architecture"
cloop init --model sonnet --instructions "Use Go, no external deps" "Build a web scraper"
```

| Flag | Default | Description |
|------|---------|-------------|
| `--max-steps` | `0` (unlimited) | Max autonomous steps. `0` = run until done or tokens exhausted |
| `--instructions` | | Additional constraints for Claude |
| `--model` | | Claude model override |

### `cloop run`

Start or continue the autonomous loop.

```bash
cloop run
cloop run --dangerously-skip-permissions
cloop run --auto-evolve
cloop run --model sonnet --step-timeout 15m
cloop run --add-steps 10  # extend max if paused at limit
cloop run --dry-run       # show prompts without executing
```

| Flag | Default | Description |
|------|---------|-------------|
| `--dangerously-skip-permissions` | `false` | Auto-approve all Claude Code actions |
| `--auto-evolve` | `false` | After goal completion, keep improving autonomously |
| `--model` | | Override model for this run |
| `--step-timeout` | `10m` | Timeout per step |
| `--max-tokens` | `0` | Max output tokens per step |
| `--add-steps` | `0` | Add more steps to max before running |
| `--dry-run` | `false` | Show prompts without running Claude |
| `-v, --verbose` | `false` | Verbose output |

**Stopping:** Press `Ctrl+C` to pause gracefully after the current step. Run `cloop run` again to resume.

### `cloop status`

Show current project status.

```
Goal:     Build a REST API with auth
Status:   evolving
Progress: 5 steps (unlimited)
Model:    sonnet
Created:  2026-05-01 14:00
Updated:  2026-05-01 14:15
```

### `cloop log`

Show step history.

```bash
cloop log              # all steps (truncated output)
cloop log --step 3     # specific step
cloop log --lines 0    # full output (no truncation)
```

### `cloop reset`

Reset progress but keep the goal.

### `cloop clean`

Remove `.cloop/` directory entirely.

## Auto-Evolve

With `--auto-evolve`, cloop enters a second phase after the goal is complete. Claude independently:

- Adds useful features
- Writes tests
- Improves code quality
- Fixes edge cases
- Adds documentation
- Optimizes performance

Each iteration focuses on **one** improvement. Runs until you press `Ctrl+C` or tokens are exhausted.

```bash
cloop init "Build a monitoring dashboard"
cloop run --dangerously-skip-permissions --auto-evolve
# Step 1: builds the project
# GOAL_COMPLETE
# Evolve #1: adds sparkline charts
# Evolve #2: adds TCP connection stats
# Evolve #3: adds unit tests
# Evolve #4: adds README
# ... keeps going until Ctrl+C
```

## Authentication

cloop loads environment variables from `.env` files automatically:

```
~/.openclaw/workspace/.env
~/.env
./.env
```

Set one of:

```bash
# Claude.ai subscription (OAuth token)
export CLAUDE_CODE_OAUTH_TOKEN=sk-ant-oat01-...

# Anthropic API key
export ANTHROPIC_API_KEY=sk-ant-api03-...
```

## State

All state is stored in `.cloop/state.json` in the project directory. It tracks:

- Goal and instructions
- Step history with outputs
- Current step count
- Status (`initialized`, `running`, `complete`, `failed`, `paused`, `evolving`)

## Error Handling

- **3 consecutive errors** → cloop stops automatically (prevents runaway loops)
- **Ctrl+C** → graceful pause after current step
- **Token exhaustion** → auto-evolve stops gracefully

## Examples

### Build a complete project from scratch

```bash
mkdir api && cd api
cloop init \
  --instructions "Use Go, chi router, GORM with SQLite, JWT auth" \
  "Build a REST API with users, posts, and comments"
cloop run --dangerously-skip-permissions --auto-evolve
```

### Refactor an existing codebase

```bash
cd my-project
cloop init --max-steps 10 "Refactor to hexagonal architecture, add interfaces, improve test coverage"
cloop run --dangerously-skip-permissions
```

### One-shot task

```bash
cd my-project
cloop init --max-steps 1 "Add comprehensive unit tests for the auth package"
cloop run --dangerously-skip-permissions
```

## License

MIT
