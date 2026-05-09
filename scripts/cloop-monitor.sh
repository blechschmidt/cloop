#!/bin/bash
# Monitor cloop-on-cloop: check health, restart if needed, enforce budget
# Runs via cron every 30 minutes

LOG="/tmp/cloop-monitor.log"
BUDGET_CAP=30
CLOOP_DIR="/root/Projects/cloop"
RUN_LOG="/tmp/cloop-run.log"
FLAG="/tmp/cloop-budget-ok"

TS=$(date -u +"%Y-%m-%d %H:%M:%S UTC")

# 1. Check budget
TOKEN=""
if [ -f /root/.claude/.credentials.json ]; then
    TOKEN=$(python3 -c "import json; print(json.load(open('/root/.claude/.credentials.json'))['claudeAiOauth']['accessToken'])" 2>/dev/null)
fi

WEEKLY=0
if [ -n "$TOKEN" ]; then
    RESP=$(curl -s --max-time 5 "https://api.anthropic.com/api/oauth/usage" \
        -H "Authorization: Bearer $TOKEN" \
        -H "anthropic-beta: oauth-2025-04-20" \
        -H "Content-Type: application/json" 2>/dev/null)
    WEEKLY=$(echo "$RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(int(d.get('seven_day',{}).get('utilization',0)))" 2>/dev/null || echo 0)
fi

if [ "$WEEKLY" -ge "$BUDGET_CAP" ]; then
    echo "$TS BUDGET_EXCEEDED weekly=${WEEKLY}% — killing cloop run" >> "$LOG"
    echo "STOP" > "$FLAG"
    pkill -SIGINT -f "cloop run" 2>/dev/null
    tail -200 "$LOG" > "$LOG.tmp" && mv "$LOG.tmp" "$LOG"
    exit 0
fi
echo "OK" > "$FLAG"

# 2. Check if cloop run is alive
CLOOP_PID=$(pgrep -f "cloop run" | head -1)

if [ -z "$CLOOP_PID" ]; then
    echo "$TS NOT_RUNNING weekly=${WEEKLY}% — restarting cloop run" >> "$LOG"
    
    cd "$CLOOP_DIR"
    CLAUDE_CODE_OAUTH_TOKEN="$TOKEN" nohup ./cloop run --auto-evolve --innovate -j 3 >> "$RUN_LOG" 2>&1 &
    NEW_PID=$!
    echo "$TS RESTARTED pid=$NEW_PID" >> "$LOG"
else
    # 3. Check if it's making progress (last modification of state.db)
    STATE_DB="$CLOOP_DIR/.cloop/state.db"
    if [ -f "$STATE_DB" ]; then
        LAST_MOD=$(stat -c %Y "$STATE_DB" 2>/dev/null || echo 0)
        NOW=$(date +%s)
        AGE=$(( (NOW - LAST_MOD) / 60 ))
        
        if [ "$AGE" -gt 60 ]; then
            echo "$TS STALE pid=$CLOOP_PID state_age=${AGE}m weekly=${WEEKLY}% — killing and restarting" >> "$LOG"
            kill -SIGINT "$CLOOP_PID" 2>/dev/null
            sleep 5
            kill -9 "$CLOOP_PID" 2>/dev/null 
            sleep 2
            
            cd "$CLOOP_DIR"
            CLAUDE_CODE_OAUTH_TOKEN="$TOKEN" nohup ./cloop run --auto-evolve --innovate -j 3 >> "$RUN_LOG" 2>&1 &
            echo "$TS RESTARTED pid=$!" >> "$LOG"
        else
            # 4. Check last few lines of log for errors
            LAST_LINES=$(tail -5 "$RUN_LOG" 2>/dev/null)
            if echo "$LAST_LINES" | grep -qi "panic\|fatal\|segfault"; then
                echo "$TS CRASH_DETECTED pid=$CLOOP_PID weekly=${WEEKLY}% — restarting" >> "$LOG"
                kill -9 "$CLOOP_PID" 2>/dev/null
                sleep 2
                cd "$CLOOP_DIR"
                CLAUDE_CODE_OAUTH_TOKEN="$TOKEN" nohup ./cloop run --auto-evolve --innovate -j 3 >> "$RUN_LOG" 2>&1 &
                echo "$TS RESTARTED pid=$!" >> "$LOG"
            else
                echo "$TS HEALTHY pid=$CLOOP_PID state_age=${AGE}m weekly=${WEEKLY}%" >> "$LOG"
            fi
        fi
    else
        echo "$TS NO_STATE_DB pid=$CLOOP_PID weekly=${WEEKLY}%" >> "$LOG"
    fi
fi

# Keep log manageable
tail -200 "$LOG" > "$LOG.tmp" && mv "$LOG.tmp" "$LOG"
