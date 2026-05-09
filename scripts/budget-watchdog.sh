#!/bin/bash
# Budget watchdog for cloop - checks Claude Code weekly usage and kills cloop run if over budget
# Run via cron every 30 seconds

BUDGET_CAP=30  # percent
FLAG_FILE="/tmp/cloop-budget-ok"
LOG_FILE="/tmp/cloop-watchdog.log"

# Get the OAuth token
TOKEN=""
if [ -f /root/.claude/.credentials.json ]; then
    TOKEN=$(python3 -c "import json; print(json.load(open('/root/.claude/.credentials.json'))['claudeAiOauth']['accessToken'])" 2>/dev/null)
fi

if [ -z "$TOKEN" ]; then
    echo "$(date -u +%H:%M:%S) NO_TOKEN" >> "$LOG_FILE"
    echo "OK" > "$FLAG_FILE"
    exit 0
fi

# Query usage API
RESP=$(curl -s --max-time 5 "https://api.anthropic.com/api/oauth/usage" \
    -H "Authorization: Bearer $TOKEN" \
    -H "anthropic-beta: oauth-2025-04-20" \
    -H "Content-Type: application/json" 2>/dev/null)

WEEKLY=$(echo "$RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(int(d.get('seven_day',{}).get('utilization',0)))" 2>/dev/null)

if [ -z "$WEEKLY" ] || [ "$WEEKLY" = "" ]; then
    echo "$(date -u +%H:%M:%S) PARSE_ERROR" >> "$LOG_FILE"
    echo "OK" > "$FLAG_FILE"
    exit 0
fi

if [ "$WEEKLY" -ge "$BUDGET_CAP" ]; then
    echo "$(date -u +%H:%M:%S) OVER_BUDGET weekly=${WEEKLY}% cap=${BUDGET_CAP}% — killing cloop run" >> "$LOG_FILE"
    echo "STOP" > "$FLAG_FILE"
    pkill -SIGINT -f "cloop run" 2>/dev/null
else
    echo "$(date -u +%H:%M:%S) OK weekly=${WEEKLY}% cap=${BUDGET_CAP}%" >> "$LOG_FILE"
    echo "OK" > "$FLAG_FILE"
fi

# Keep log small
tail -100 "$LOG_FILE" > "$LOG_FILE.tmp" && mv "$LOG_FILE.tmp" "$LOG_FILE"
