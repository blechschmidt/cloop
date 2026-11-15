#!/usr/bin/env bash
# run.sh — move a project from a hub to a real device and back, with work in
# flight at each end, and check that nothing was lost. See README.md.
#
#   BIN=/path/to/static/cloop DEVICE=sgx ./run.sh
#
# Everything runs under WORK (a fresh directory by default) with its own HOME
# and CLOOP_HOME, a hub of its own on 127.0.0.1:PORT reached by the device over
# `ssh -R`, and a second agent on the device under RDIR. The device's own agent
# and anything else on either host are left alone. Exit status 0 means every
# check passed; the transcript is WORK/results.log.
set -euo pipefail

BIN=${BIN:?BIN names the static cloop under test}
DEVICE=${DEVICE:-sgx}
PORT=${PORT:-18497}
FORGE_PORT=${FORGE_PORT:-18498}
WORK=${WORK:-$(mktemp -d /tmp/cloop-projectmove-rig-XXXXXX)}
RDIR=${RDIR:-/tmp/cloop-projectmove-rig}
KIT=$(cd "$(dirname "$0")" && pwd)
TOKEN=rig-$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')
BASE=http://127.0.0.1:$PORT
RESULTS=$WORK/results.log
FAILED=0

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

PIDS=()
teardown() {
  set +e
  ssh "$DEVICE" "pid=\$(cat $RDIR/agent.pid 2>/dev/null); [ -n \"\$pid\" ] && kill \$pid; sleep 1; rm -rf $RDIR" >/dev/null 2>&1
  for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done
  wait 2>/dev/null
  log "torn down (hub, forge, tunnel, the device's test agent and $RDIR)"
}
trap teardown EXIT

export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=$WORK/home/.gitconfig GIT_TERMINAL_PROMPT=0
printf '[user]\n\tname = Rig\n\temail = rig@example.com\n[init]\n\tdefaultBranch = main\n[safe]\n\tdirectory = *\n' >"$GIT_CONFIG_GLOBAL"
install -m 0755 "$KIT/claude" "$WORK/hub-bin/claude"
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
dev() { ssh "$DEVICE" "$@"; }
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
add_task() { # add_task TITLE → id
  api POST "/api/tasks?project_idx=$(idx)" "{\"title\":\"$1\",\"description\":\"$1\"}" >/dev/null
  api GET "/api/state?project_idx=$(idx)" | jq_ "max(t['id'] for t in d['plan']['tasks'])"
}
run_project() { api POST "/api/projects/$(idx)/run" '{}' >/dev/null; }
idle() { api GET /api/projects | jq_ "[p for p in d['projects'] if p['path']=='$WORK/proj'][0]['status'] not in ('running','starting','evolving')" | grep -q True; }

log "rig: hub $BASE, device $DEVICE (second agent under $RDIR), work $WORK"
log "cloop under test: $("$BIN" version 2>/dev/null | head -1)"

# ── the forge, the project and the hub ───────────────────────────────────────
(cd "$KIT" && go build -o "$WORK/forge-bin" forge.go)
("$WORK/forge-bin" -listen "127.0.0.1:$FORGE_PORT" -root "$WORK/forge" -ca "$WORK/forge-ca.pem" >"$WORK/forge.log" 2>&1) &
PIDS+=($!)
wait_for "the forge" 20 test -s "$WORK/forge-ca.pem"
ORIGIN=https://127.0.0.1:$FORGE_PORT/srv/acme/app.git
git init -q --bare -b main "$WORK/forge/srv/acme/app.git"

P=$WORK/proj
git -C "$P" init -q -b main
printf '# app\n' >"$P/README.md"
mkdir -p "$P/src" "$P/docs" "$P/assets"
printf 'package main\n\nfunc main() {}\n' >"$P/src/main.go"
printf 'package main\n\nfunc util() int { return 1 }\n' >"$P/src/util.go"
printf 'renamed later\n' >"$P/docs/old-name.md"
head -c 4096 /dev/urandom >"$P/assets/logo.bin"
git -C "$P" add -A && git -C "$P" commit -qm first
git -C "$P" remote add origin "$ORIGIN"
git -C "$P" push -q "$WORK/forge/srv/acme/app.git" main:refs/heads/main
git -C "$P" update-ref refs/remotes/origin/main refs/heads/main
(cd "$P" && cl init --provider claudecode --skip-clarify "Move between the hub and a device" >/dev/null)
(cd "$WORK/hub" && cl init --provider mock --skip-clarify hub >/dev/null)
# The Claude credential a claudecode run on the device needs: granted first,
# as the hub refuses the dispatch without one. The stand-in claude ignores it.
(cd "$WORK/hub" && cl secret mint rig-claude --kind env \
  --value '{"CLAUDE_CODE_OAUTH_TOKEN":"sk-ant-oat01-rigplaceholderrigplaceholder"}' >/dev/null &&
  cl secret grant rig-claude --to "project:$P" --env-keys CLAUDE_CODE_OAUTH_TOKEN --ttl 4h >/dev/null)

(cd "$WORK/hub" && exec "${HUBENV[@]}" "$BIN" ui --listen 127.0.0.1 --port "$PORT" --no-browser --projects "$P" >"$WORK/hub.log" 2>&1) &
PIDS+=($!)
wait_for "the hub" 60 curl -sf -H "Authorization: Bearer $TOKEN" "$BASE/api/executors"

# ── the device: a second agent, reached over a reverse tunnel ───────────────
ssh -N -o ExitOnForwardFailure=yes -R "$PORT:127.0.0.1:$PORT" -R "$FORGE_PORT:127.0.0.1:$FORGE_PORT" "$DEVICE" &
PIDS+=($!)
(cd "$WORK/hub" && cl executor enroll --name rig-device --server "ws://127.0.0.1:$PORT/api/executors/connect" \
  --bundle-file "$WORK/bundle" >/dev/null)
dev "rm -rf $RDIR && mkdir -p $RDIR/bin $RDIR/home $RDIR/work"
scp -q "$BIN" "$DEVICE:$RDIR/bin/cloop"
scp -q "$KIT/claude" "$KIT/snap.sh" "$DEVICE:$RDIR/bin/"
scp -q "$WORK/bundle" "$WORK/forge-ca.pem" "$DEVICE:$RDIR/"
dev "chmod 0755 $RDIR/bin/*; cd $RDIR && setsid -f sh -c 'echo \$\$ >$RDIR/agent.pid; exec env -i HOME=$RDIR/home \
  PATH=$RDIR/bin:/usr/local/bin:/usr/bin:/bin GIT_SSL_CAINFO=$RDIR/forge-ca.pem $RDIR/bin/cloop executor agent \
  --token-file $RDIR/bundle --credential $RDIR/agent.json --workdir-root $RDIR/work' >$RDIR/agent.log 2>&1 </dev/null"
online() { api GET /api/executors | jq_ "[e['id'] for e in d['executors'] if e['name']=='rig-device' and e['status']=='online']" | grep -q "'"; }
wait_for "the device's agent to connect" 60 online
DEVICE_ID=$(api GET /api/executors | jq_ "[e['id'] for e in d['executors'] if e['name']=='rig-device'][0]")
log "device $DEVICE is executor $DEVICE_ID; its agent: $(dev "$RDIR/bin/cloop version" | head -1)"

# ── the starting state: a task with an attachment, and a feature ────────────
T1=$(add_task "Write the first report")
run_project
wait_for "task $T1 on the hub" 120 task_done "$T1"
wait_for "the run to end" 60 idle
api POST "/api/projects/$(idx)/features" '{"name":"Widget","description":"Build the widget"}' >/dev/null
F=$P/.cloop/features/widget
check "the hub made the feature's worktree" test -e "$F/.git"

# prepare SIDE DIR K: a task held in progress, a commit on main and one on the
# feature branch that no remote has, and a dirty tree.
on() { if [ "$1" = device ]; then dev "$2"; else sh -c "$2"; fi; }
prepare() {
  local side=$1 dir=$2 k=$3
  HOLD=$(add_task "Move $k: HOLD-UNTIL-MOVED")
  on "$side" "touch $dir/.cloop/e2e-hold; rm -f $dir/.cloop/e2e-holding"
  run_project
  holding() { on "$side" "grep -q ' $HOLD\$' $dir/.cloop/e2e-holding"; }
  wait_for "task $HOLD to be in progress on the $side" 180 holding
  on "$side" "cd $dir && git -c user.name=Rig -c user.email=rig@example.com checkout -q main 2>/dev/null; \
    printf 'package main\n\nfunc move$k() {}\n' > src/move$k.go && git add src && \
    git -c user.name=Rig -c user.email=rig@example.com commit -qm 'move $k: a commit no remote has' && \
    printf 'edited before move $k\n' >> README.md && rm -f src/util.go && \
    { [ -e docs/old-name.md ] && git mv docs/old-name.md docs/renamed-$k.md || git mv docs/renamed-$((k - 1)).md docs/renamed-$k.md; } && \
    mkdir -p notes && echo 'untracked draft $k' > notes/draft-$k.md && head -c 3000 /dev/urandom > assets/logo.bin && \
    printf 'staged before move $k\n' > src/main.go && git add src/main.go && printf 'and edited again\n' >> src/main.go && \
    mkdir -p .cloop/artifacts && echo 'output kept for move $k' > .cloop/artifacts/move-${k}_output.txt"
  printf 'widget, move %s\n' "$k" >"$F/widget-$k.txt"
  git -C "$F" add "widget-$k.txt" && git -C "$F" commit -qm "widget: move $k"
  FEATURE_TIP=$(git -C "$F" rev-parse HEAD)
}
snap() { # snap SIDE DIR → the working copy's facts, minus the held task's own artifacts
  if [ "$1" = device ]; then dev "$RDIR/bin/snap.sh $2"; else "$KIT/snap.sh" "$2"; fi |
    grep -v "^extra artifacts/${HOLD}_" | grep -v "^extra artifacts/${HOLD}-"
}
move_to() { # move_to TARGET → move id; the transcript goes to the results
  local out
  out=$(cl executor move "$(idx)" --to "$1" --yes --hub "$BASE" --token "$TOKEN" 2>&1) || {
    echo "$out" >>"$RESULTS"
    die "cloop executor move --to $1 failed"
  }
  echo "$out" >>"$RESULTS"
  echo "$out" | sed -n 's/.*(move \([0-9a-f]\{16\}\)).*/\1/p' | head -1
}
move_json() { api GET "/api/projects/$(idx)/move/$1"; }
outcome() { move_json "$1" | jq_ "d['move']['phase']+'/'+str(len((d['move']['detail'].get('verify') or {}).get('mismatches') or []))"; }
attachments_of() { api GET "/api/tasks/$1/attachments?project_idx=$(idx)"; }

# ── 1. the hub → the device ─────────────────────────────────────────────────
prepare hub "$P" 1
snap hub "$P" >"$WORK/before-1.txt"
log "move 1: the hub → device $DEVICE_ID"
M1=$(move_to "$DEVICE_ID")
DCOPY=$(move_json "$M1" | jq_ "d['move']['detail']['seed']['work_dir']")
DCOPY=$RDIR/work/$DCOPY
check "move 1 is done and verified" test "$(outcome "$M1")" = done/0
check "task $HOLD went back to pending" test "$(status_of "$HOLD")" = pending
snap device "$DCOPY" >"$WORK/after-1.txt"
check "the device holds byte for byte what the hub held (tree, index, HEAD, branches, .cloop files)" \
  diff -u "$WORK/before-1.txt" "$WORK/after-1.txt"
snap hub "$P" >"$WORK/kept-1.txt"
check "the hub keeps its copy as it was until cleanup" diff -u "$WORK/before-1.txt" "$WORK/kept-1.txt"
rm -f "$P/.cloop/e2e-hold"
run_project
wait_for "task $HOLD to run on the device" 300 task_done "$HOLD"
wait_for "the run to end" 120 idle
check "the next task ran in the device's working copy" dev "test -s $DCOPY/ran-$HOLD.txt"
check "it ran on top of the moved work (HEAD still on main with the unpushed commit)" \
  dev "cd $DCOPY && GIT_CONFIG_GLOBAL=/dev/null git symbolic-ref HEAD | grep -q refs/heads/main && test -e src/move1.go"
check "its report came back as an attachment" grep -q "report-$HOLD.txt" <<<"$(attachments_of "$HOLD")"
check "the first task's attachment is still there" grep -q "report-$T1.txt" <<<"$(attachments_of "$T1")"
cl executor move cleanup "$M1" --yes --hub "$BASE" --token "$TOKEN" >>"$RESULTS" 2>&1 || FAILED=1
check "cleanup removed move 1's hidden refs and kept the hub's directory" \
  sh -c "! git -C $P rev-parse -q --verify refs/cloop/move/$M1 && test -d $P/.git"

# ── 2. the device → the hub ─────────────────────────────────────────────────
prepare device "$DCOPY" 2
snap device "$DCOPY" | sed "s#^ref refs/heads/cloop/feature/widget .*#ref refs/heads/cloop/feature/widget $FEATURE_TIP#" >"$WORK/before-2.txt"
cl executor move "$(idx)" --to local --dry-run --hub "$BASE" --token "$TOKEN" >"$WORK/preflight-2.txt" 2>&1 || true
cat "$WORK/preflight-2.txt" >>"$RESULTS"
check "the preflight says the hub's directory still holds the copy the project left" \
  grep -q "still holds the copy the project left there" "$WORK/preflight-2.txt"
log "move 2: device $DEVICE_ID → the hub"
M2=$(move_to local)
check "move 2 is done and verified" test "$(outcome "$M2")" = done/0
check "task $HOLD went back to pending" test "$(status_of "$HOLD")" = pending
snap hub "$P" >"$WORK/after-2.txt"
check "the hub holds byte for byte what the device held, with the feature branch the hub moved on kept" \
  diff -u "$WORK/before-2.txt" "$WORK/after-2.txt"
check "the feature's worktree is still registered and clean" sh -c "[ -z \"\$(git -C $F status --porcelain)\" ] && [ \"\$(git -C $F rev-parse HEAD)\" = $FEATURE_TIP ]"
check "the device keeps its copy until cleanup" dev "test -d $DCOPY/.git"
run_project
wait_for "task $HOLD to run on the hub" 120 task_done "$HOLD"
wait_for "the run to end" 60 idle
check "the next task ran in the hub's directory" test -s "$P/ran-$HOLD.txt"
cl executor move cleanup "$M2" --yes --hub "$BASE" --token "$TOKEN" >>"$RESULTS" 2>&1 || FAILED=1
check "cleanup of the verified move removed the device's copy" dev "[ -z \"\$(ls -A $DCOPY 2>/dev/null)\" ]"

if [ "$FAILED" = 0 ]; then log "ALL CHECKS PASSED"; else log "SOME CHECKS FAILED"; fi
exit "$FAILED"
