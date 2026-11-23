#!/usr/bin/env bash
# run.sh — a run on a remote executor is given a task's input file and attaches
# files far bigger than its result can carry; check that every one reaches the
# hub whole, scrubbed and once. See README.md.
#
#   BIN=/path/to/static/cloop ./run.sh                 # the second agent on this host
#   BIN=/path/to/static/cloop DEVICE=sgx ./run.sh      # the second agent on a device
#   BIN=… RUN_BIN=/path/to/older/cloop ./run.sh        # the run's own cloop is another one
#
# RUN_BIN is the cloop the device runs the project with (`cloop run`, found on
# the payload's PATH); the hub and the device's agent run BIN. It defaults to
# BIN. Give it a build from before runs sent their files (Task 20513) to check
# that the agent sends what such a run leaves behind (Task 20515).
#
# Everything runs under WORK (a fresh directory by default) with its own HOME
# and CLOOP_HOME, and a hub of its own on 127.0.0.1:PORT. With DEVICE=local the
# second agent runs on this host under WORK/device; with an ssh host it runs
# there under RDIR and reaches the hub and the project's origin over `ssh -R`.
# Nothing else on either host is touched. Exit status 0 means every check
# passed; the transcript is WORK/results.log.
set -euo pipefail

BIN=${BIN:?BIN names the static cloop under test}
RUN_BIN=${RUN_BIN:-$BIN}
DEVICE=${DEVICE:-local}
PORT=${PORT:-18513}
FORGE_PORT=${FORGE_PORT:-18514}
WORK=${WORK:-$(mktemp -d /tmp/cloop-attachments-rig-XXXXXX)}
if [ "$DEVICE" = local ]; then
  RDIR=${RDIR:-$WORK/device}
else
  RDIR=${RDIR:-/tmp/cloop-attachments-rig}
fi
KIT=$(cd "$(dirname "$0")" && pwd)
TOKEN=rig-$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')
BASE=http://127.0.0.1:$PORT
RESULTS=$WORK/results.log
FAILED=0
# The credential a claudecode run on a device needs, as a placeholder: the
# stand-in harness never uses it, and the hub must scrub it from every file.
CLAUDE_PLACEHOLDER=sk-ant-oat01-rigplaceholder20513rigplaceholder

mkdir -p "$WORK"/{home,hub,proj,hub-bin,forge}
# Every local cloop runs here: a cloop started in a project directory opens
# that directory's database, and the rig must open no database but its own.
cd "$WORK"

log() { printf '%s %s\n' "$(date -u +%H:%M:%S)" "$*" | tee -a "$RESULTS"; }
check() { # check DESCRIPTION CONDITION...
  local what=$1
  shift
  if "$@"; then
    log "PASS $what"
  else
    log "FAIL $what"
    FAILED=1
  fi
}
die() {
  log "ABORT $*"
  exit 1
}

dev() { if [ "$DEVICE" = local ]; then sh -c "$1"; else ssh "$DEVICE" "$1"; fi; }
put() { if [ "$DEVICE" = local ]; then cp "$@"; else scp -q "$@"; fi; }
dest() { if [ "$DEVICE" = local ]; then echo "$1"; else echo "$DEVICE:$1"; fi; }

PIDS=()
teardown() {
  set +e
  dev "pid=\$(cat $RDIR/agent.pid 2>/dev/null); [ -n \"\$pid\" ] && kill \$pid; sleep 1" >/dev/null 2>&1
  for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done
  wait 2>/dev/null
  [ "$DEVICE" = local ] || dev "rm -rf $RDIR" >/dev/null 2>&1
  log "torn down (hub, forge, the second agent$([ "$DEVICE" = local ] || echo ", the tunnel and $RDIR on $DEVICE"))"
}
trap teardown EXIT

export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=$WORK/home/.gitconfig GIT_TERMINAL_PROMPT=0
printf '[user]\n\tname = Rig\n\temail = rig@example.com\n[init]\n\tdefaultBranch = main\n[safe]\n\tdirectory = *\n' >"$GIT_CONFIG_GLOBAL"
HUBENV=(env -i HOME="$WORK/home" CLOOP_HOME="$WORK/home/.cloop" PATH="$WORK/hub-bin:/usr/local/bin:/usr/bin:/bin"
  CLOOP_UI_TOKEN="$TOKEN" CLOOP_SECRET_KEY="rig-$TOKEN" GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL="$GIT_CONFIG_GLOBAL"
  GIT_TERMINAL_PROMPT=0 NO_COLOR=1)
cl() { "${HUBENV[@]}" "$BIN" "$@"; }
api() { # api METHOD PATH [JSON]
  if [ $# -ge 3 ]; then
    curl -sS -X "$1" -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' --data "$3" "$BASE$2"
  else
    curl -sS -X "$1" -H "Authorization: Bearer $TOKEN" "$BASE$2"
  fi
}
wait_for() { # wait_for DESCRIPTION SECONDS COMMAND...
  local what=$1 secs=$2
  shift 2
  local end=$((SECONDS + secs))
  until "$@" >/dev/null 2>&1; do
    [ $SECONDS -lt $end ] || die "timed out after ${secs}s waiting for $what"
    sleep 1
  done
}
jq_() { python3 -c "import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1]))" "$1"; }
idx() { api GET /api/projects | jq_ "[i for i,p in enumerate(d['projects']) if p['path']=='$WORK/proj'][0]"; }
status_of() { api GET "/api/state?project_idx=$(idx)" | jq_ "[t['status'] for t in d['plan']['tasks'] if t['id']==$1][0]"; }
task_done() { [ "$(status_of "$1")" = "done" ]; }
idle() { api GET /api/projects | jq_ "[p for p in d['projects'] if p['path']=='$WORK/proj'][0]['status'] not in ('running','starting','evolving')" | grep -q True; }
attachments_of() { api GET "/api/tasks/$1/attachments?project_idx=$(idx)"; }
row_of() { # row_of TASK NAME FIELD
  attachments_of "$1" | jq_ "([a.get('$3','') for a in d['attachments'] if a['name']=='$2'] or ['<none>'])[0]"
}
fetch() { # fetch TASK NAME OUT — the bytes the hub serves for the file
  local aid
  aid=$(row_of "$1" "$2" id)
  curl -sS -o "$3" -H "Authorization: Bearer $TOKEN" "$BASE/api/tasks/$1/attachments/$aid?project_idx=$(idx)"
}

log "rig: hub $BASE, device $DEVICE (second agent under $RDIR), work $WORK"
log "cloop under test: $("$BIN" version 2>/dev/null | head -1)"
[ "$RUN_BIN" = "$BIN" ] || log "the device runs the project with: $("$RUN_BIN" version 2>/dev/null | head -1) ($RUN_BIN)"

# ── the forge, the project and the hub ───────────────────────────────────────
(cd "$KIT/../projectmove" && go build -o "$WORK/forge-bin" forge.go)
("$WORK/forge-bin" -listen "127.0.0.1:$FORGE_PORT" -root "$WORK/forge" -ca "$WORK/forge-ca.pem" >"$WORK/forge.log" 2>&1) &
PIDS+=($!)
wait_for "the forge" 20 test -s "$WORK/forge-ca.pem"
ORIGIN=https://127.0.0.1:$FORGE_PORT/srv/acme/app.git
git init -q --bare -b main "$WORK/forge/srv/acme/app.git"

P=$WORK/proj
git -C "$P" init -q -b main
printf '# app\n' >"$P/README.md"
git -C "$P" add -A && git -C "$P" commit -qm first
git -C "$P" remote add origin "$ORIGIN"
git -C "$P" push -q "$WORK/forge/srv/acme/app.git" main:refs/heads/main
git -C "$P" update-ref refs/remotes/origin/main refs/heads/main
(cd "$P" && cl init --provider claudecode --skip-clarify "Attach reports from a device" >/dev/null)
(cd "$WORK/hub" && cl init --provider mock --skip-clarify hub >/dev/null)
# The run session's address: the hub's public URL, which the device reaches on
# its own loopback (directly, or through the tunnel).
printf 'ui:\n  external_url: %s\n' "$BASE" >>"$WORK/hub/.cloop/config.yaml"
(cd "$WORK/hub" && cl secret mint rig-claude --kind env \
  --value "{\"CLAUDE_CODE_OAUTH_TOKEN\":\"$CLAUDE_PLACEHOLDER\"}" >/dev/null &&
  cl secret grant rig-claude --to "project:$P" --env-keys CLAUDE_CODE_OAUTH_TOKEN --ttl 4h >/dev/null)

(cd "$WORK/hub" && exec "${HUBENV[@]}" "$BIN" ui --listen 127.0.0.1 --port "$PORT" --no-browser --projects "$P" >"$WORK/hub.log" 2>&1) &
PIDS+=($!)
wait_for "the hub" 60 curl -sf -H "Authorization: Bearer $TOKEN" "$BASE/api/executors"

# ── the device: a second agent ───────────────────────────────────────────────
if [ "$DEVICE" != local ]; then
  ssh -N -o ExitOnForwardFailure=yes -R "$PORT:127.0.0.1:$PORT" -R "$FORGE_PORT:127.0.0.1:$FORGE_PORT" "$DEVICE" &
  PIDS+=($!)
fi
(cd "$WORK/hub" && cl executor enroll --name rig-device --server "ws://127.0.0.1:$PORT/api/executors/connect" \
  --bundle-file "$WORK/bundle" >/dev/null)
# The agent runs BIN from agent-bin; the run finds RUN_BIN as `cloop` in bin.
dev "rm -rf $RDIR && mkdir -p $RDIR/bin $RDIR/agent-bin $RDIR/home $RDIR/work"
put "$BIN" "$(dest "$RDIR/agent-bin/cloop")"
put "$RUN_BIN" "$(dest "$RDIR/bin/cloop")"
put "$KIT/claude" "$(dest "$RDIR/bin/claude")"
put "$WORK/bundle" "$WORK/forge-ca.pem" "$(dest "$RDIR/")"
dev "chmod 0755 $RDIR/bin/* $RDIR/agent-bin/*; cd $RDIR && setsid -f sh -c 'echo \$\$ >$RDIR/agent.pid; exec env -i HOME=$RDIR/home \
  PATH=$RDIR/bin:/usr/local/bin:/usr/bin:/bin GIT_SSL_CAINFO=$RDIR/forge-ca.pem $RDIR/agent-bin/cloop executor agent \
  --token-file $RDIR/bundle --credential $RDIR/agent.json --workdir-root $RDIR/work' >$RDIR/agent.log 2>&1 </dev/null"
online() { api GET /api/executors | jq_ "[e['id'] for e in d['executors'] if e['name']=='rig-device' and e['status']=='online']" | grep -q "'"; }
wait_for "the device's agent to connect" 60 online
DEVICE_ID=$(api GET /api/executors | jq_ "[e['id'] for e in d['executors'] if e['name']=='rig-device'][0]")
log "the device is executor $DEVICE_ID"
api POST "/api/projects/$(idx)/executor" "{\"executor_id\":\"$DEVICE_ID\"}" >/dev/null

# ── a task with an input file, run on the device ─────────────────────────────
api POST "/api/tasks?project_idx=$(idx)" '{"title":"Write the reports","description":"Write the reports"}' >/dev/null
T=$(api GET "/api/state?project_idx=$(idx)" | jq_ "max(t['id'] for t in d['plan']['tasks'])")
printf 'the specification the agent works from, %s\n' "$TOKEN" >"$WORK/spec.txt"
curl -sS -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/octet-stream' \
  --data-binary @"$WORK/spec.txt" "$BASE/api/tasks/$T/attachments?name=spec.txt&project_idx=$(idx)" >/dev/null
check "spec.txt is an input file of task $T" test "$(row_of "$T" spec.txt role)" = input
api POST "/api/projects/$(idx)/run" '{}' >/dev/null
wait_for "task $T on the hub" 240 task_done "$T"
wait_for "the run to end" 120 idle
sleep 2

# ── what reached the hub ─────────────────────────────────────────────────────
attachments_of "$T" | jq_ "'\n'.join('%-16s %-6s %9s %s' % (a['name'], a.get('role') or 'result', a['size'], a.get('unavailable') or 'on the hub') for a in d['attachments'])" |
  sed 's/^/    /' | tee -a "$RESULTS"
python3 -c 'import random, sys; sys.stdout.buffer.write(random.Random(20513).randbytes(2 << 20))' >"$WORK/big.expected"
fetch "$T" plots/big.bin "$WORK/big.got"
check "plots/big.bin (2 MiB, more than a run's result carries) is on the hub" test "$(row_of "$T" plots/big.bin unavailable)" = ""
check "the hub serves plots/big.bin byte for byte" cmp -s "$WORK/big.expected" "$WORK/big.got"
fetch "$T" report.md "$WORK/report.got"
check "report.md is on the hub" grep -q "Report of task $T" "$WORK/report.got"
check "report.md is scrubbed of the credential the run was leased" sh -c "! grep -q '$CLAUDE_PLACEHOLDER' '$WORK/report.got'"
fetch "$T" echo.txt "$WORK/echo.got"
check "the agent on the device worked from the input file (echo.txt = spec.txt)" cmp -s "$WORK/spec.txt" "$WORK/echo.got"
check "small.txt is on the hub" test "$(row_of "$T" small.txt unavailable)" = ""
n=$(attachments_of "$T" | jq_ "len([a for a in d['attachments'] if (a.get('role') or '')==''])")
check "each result is attached once ($n results)" test "$n" = 4
DB=$WORK/hub/.cloop/state.db
uploads=$(python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); print(c.execute(\"select count(*) from audit_events where event_type='run.result_upload' and payload like '%\\\"outcome\\\":\\\"attached\\\"%'\").fetchone()[0])" "$DB")
check "the hub audited each file the run sent as attached ($uploads)" test "$uploads" = 4
fetches=$(python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); print(c.execute(\"select count(*) from audit_events where event_type='run.input_fetch' and payload like '%\\\"outcome\\\":\\\"ok\\\"%'\").fetchone()[0])" "$DB")
check "the hub audited the input file the run fetched ($fetches)" test "$fetches" -ge 1
merged=$(python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); r=c.execute(\"select message from events where type='project_result' order by id desc limit 1\").fetchone(); print(r[0] if r else '')" "$P/.cloop/state.db")
log "the merge: $merged"
check "the merge counted the files the run had already sent" sh -c "printf '%s' \"\$1\" | grep -q 'already sent while it ran'" _ "$merged"
held=$( (find "$P/.cloop/attachments/held" -type f 2>/dev/null || true) | wc -l)
check "nothing is left held on the hub ($held)" test "$held" = 0
if [ "$RUN_BIN" != "$BIN" ]; then
  # A run whose cloop predates sending sends nothing itself: every file on the
  # hub came from the agent, once the run had ended.
  agentlog=$(dev "cat $RDIR/agent.log" 2>/dev/null || true)
  printf '%s\n' "$agentlog" | grep "attached files to the hub" | sed 's/^/    agent: /' | tee -a "$RESULTS"
  check "the device's agent sent the four files the run left behind" \
    sh -c "printf '%s' \"\$1\" | grep -q 'sent 4 of the run.s attached files to the hub'" _ "$agentlog"
fi

if [ "$FAILED" = 0 ]; then log "ALL PASSED"; else log "SOME CHECKS FAILED"; fi
exit "$FAILED"
