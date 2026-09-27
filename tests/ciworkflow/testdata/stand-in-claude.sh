#!/usr/bin/env bash
# A stand-in for Claude Code on a machine that has none (see main_test.go).
#
# It makes the one request Claude Code 2.1 makes for `-p PROMPT`: a streamed
# POST to $ANTHROPIC_BASE_URL/v1/messages?beta=true, authenticated with
# ANTHROPIC_AUTH_TOKEN as a bearer (or ANTHROPIC_API_KEY as x-api-key), for the
# model --model names — resolving the same aliases, and falling back to the same
# default, that Claude Code does. It then prints the streamed text, or
# "API Error: <status> <body>" and exits 1, as Claude Code does.
#
# What it proves is the relay's API path as a harness uses it. What it cannot
# prove is anything about the harness, which is why the suite reports when it
# ran this instead of Claude Code.
set -euo pipefail

model="" prompt=""
while [ $# -gt 0 ]; do
  case "$1" in
    --model) model="$2"; shift 2 ;;
    -p|--print) prompt="$2"; shift 2 ;;
    *) echo "stand-in-claude: unsupported argument $1" >&2; exit 2 ;;
  esac
done
[ -n "$prompt" ] || { echo "stand-in-claude: -p PROMPT is required" >&2; exit 2; }

case "$model" in
  "" | opus) model=claude-opus-5-5 max=128000 ;;
  sonnet) model=claude-sonnet-5 max=64000 ;;
  haiku) model=claude-haiku-4-5-20251001 max=32000 ;;
  *) max=32000 ;;
esac

auth=()
if [ -n "${ANTHROPIC_AUTH_TOKEN:-}" ]; then
  auth=(-H "authorization: Bearer $ANTHROPIC_AUTH_TOKEN")
elif [ -n "${ANTHROPIC_API_KEY:-}" ]; then
  auth=(-H "x-api-key: $ANTHROPIC_API_KEY")
fi

body=$(jq -cn --arg model "$model" --argjson max "$max" --arg prompt "$prompt" \
  '{model: $model, max_tokens: $max, stream: true, messages: [{role: "user", content: $prompt}]}')
out=$(mktemp)
trap 'rm -f "$out"' EXIT
status=$(curl -sS -N -o "$out" -w '%{http_code}' -X POST \
  "${ANTHROPIC_BASE_URL:-https://api.anthropic.com}/v1/messages?beta=true" \
  "${auth[@]}" \
  -H 'anthropic-version: 2023-06-01' \
  -H 'anthropic-beta: claude-code-20250219' \
  -H 'content-type: application/json' \
  --data-binary "$body")
if [ "$status" != 200 ]; then
  echo "API Error: $status $(cat "$out")"
  exit 1
fi
sed -n 's/^data: //p' "$out" \
  | jq -rj 'select(.type == "content_block_delta" and .delta.type == "text_delta") | .delta.text'
echo
