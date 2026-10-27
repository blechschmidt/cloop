#!/usr/bin/env bash
# run.sh — a device installs the GitHub Copilot CLI on request, then runs a
# copilot task (Task 20450). See README.md for what each check proves.
#
#   scripts/e2e/copilot-device/run.sh            against the device `sgx`
#   DEVICE=host scripts/e2e/copilot-device/run.sh
#
# Everything it starts is its own and is torn down on exit: a hub on this host
# (its own HOME, workdir, port and token, bound to loopback), an `ssh -R` tunnel
# so the device's agent dials loopback, and on the device a second agent — the
# cloop under test, run as the production agent's user with a HOME of its own
# that has no copilot in it — beside a stand-in model on the device's loopback.
# The production agent and anything else on the device are left alone.
#
# Environment: DEVICE (ssh host, default sgx), PORT (the hub, tunnelled; default
# 18450), STUB_PORT (the model on the device; default 18451), AGENT_USER (default
# cloop-executor), BIN (a static build of the cloop under test; built if unset),
# KEEP=1 (leave the local tree and the device's directory for a look).
set -euo pipefail

DEVICE=${DEVICE:-sgx}
PORT=${PORT:-18450}
STUB_PORT=${STUB_PORT:-18451}
AGENT_USER=${AGENT_USER:-cloop-executor}
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../../.." && pwd)
ROOT=$(mktemp -d /tmp/cloop-copilot-device.XXXXXX)
REMOTE=/tmp/cloop-copilot-device-$PORT
HUB=$ROOT/hub PROJ=$ROOT/proj
TOKEN=$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')
KEY=$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')
API=http://127.0.0.1:$PORT
hub_pid='' tunnel_pid='' failures=0

say() { printf '\n== %s\n' "$*"; }
check() { # check NAME COMMAND... — one PASS or FAIL line per claim
	local name=$1; shift
	if "$@"; then echo "PASS  $name"; else echo "FAIL  $name"; failures=$((failures + 1)); fi
}

# Every local cloop runs with an environment built here, never this shell's: a
# hub's child process inherits CLOOP_SECRET_KEY and, on an SSO hub's host,
# CLOOP_COPILOT_HOME, either of which would make this rig test something else.
local_cloop() { (cd "$1" && shift && env -i HOME="$ROOT/home" CLOOP_HOME="$ROOT/home/.cloop" \
	PATH=/usr/local/bin:/usr/bin:/bin CLOOP_SECRET_KEY="$KEY" CLOOP_UI_TOKEN="$TOKEN" NO_COLOR=1 \
	"$BIN" "$@"); }
api() { # api METHOD PATH [JSON] — prints the body, then the status on its own line
	curl -sS -X "$1" -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
		${3:+--data "$3"} -w '\n%{http_code}\n' "$API$2"
}
remote() { ssh -o BatchMode=yes "$DEVICE" "$@"; }

teardown() {
	set +e
	say "teardown"
	# By the PIDs it recorded, never by a pattern: a pattern on the device would
	# match the ssh shell running it, and the production agent runs as the same
	# user from a similar command line.
	remote "for f in $REMOTE/agent.pid $REMOTE/stub.pid; do
			[ -f \$f ] && { kill -- -\$(cat \$f) 2>/dev/null || kill \$(cat \$f) 2>/dev/null; }; done; sleep 1;
		[ '${KEEP:-}' = 1 ] || rm -rf $REMOTE" || true
	[ -n "$tunnel_pid" ] && kill "$tunnel_pid" 2>/dev/null
	[ -n "$hub_pid" ] && kill "$hub_pid" 2>/dev/null && wait "$hub_pid" 2>/dev/null
	if [ "${KEEP:-}" = 1 ]; then echo "kept $ROOT and $DEVICE:$REMOTE"; else rm -rf "$ROOT"; fi
}
trap teardown EXIT

if [ -z "${BIN:-}" ]; then
	say "building the cloop under test (static, for the device)"
	BIN=$ROOT/cloop
	(cd "$REPO" && CGO_ENABLED=0 go build -trimpath -o "$BIN" .)
fi
"$BIN" version | head -1

say "the hub: a copilot project on a device, auto-install OFF"
mkdir -p "$HUB" "$PROJ" "$ROOT/home"
local_cloop "$HUB" init --provider mock --skip-clarify "copilot device rig" >/dev/null
printf '\nexecutors:\n    auto_install_harness: false\n' >> "$HUB/.cloop/config.yaml"
local_cloop "$PROJ" init --provider copilot --skip-clarify "Greet from the device" >/dev/null
# A provider of the project's own needs the model named.
local_cloop "$PROJ" config set copilot.model rig-stub-model >/dev/null
local_cloop "$PROJ" task add "Write copilot-hello.txt in the working directory" --no-ai --auto >/dev/null
# The run's Copilot credential: the stand-in model on the device's loopback,
# offline — no GitHub account, no Copilot seat.
local_cloop "$HUB" secret mint rig-copilot --kind env --value \
	"{\"COPILOT_PROVIDER_BASE_URL\":\"http://127.0.0.1:$STUB_PORT/v1\",\"COPILOT_PROVIDER_API_KEY\":\"rig-key\",\"COPILOT_OFFLINE\":\"true\"}" >/dev/null
local_cloop "$HUB" secret grant rig-copilot --to "project:$PROJ" \
	--env-keys COPILOT_PROVIDER_BASE_URL,COPILOT_PROVIDER_API_KEY,COPILOT_OFFLINE --ttl 2h >/dev/null
local_cloop "$HUB" executor enroll --name rig-copilot --server "ws://127.0.0.1:$PORT/api/executors/connect" \
	--bundle-file "$ROOT/bundle" >/dev/null
(cd "$HUB" && exec env -i HOME="$ROOT/home" CLOOP_HOME="$ROOT/home/.cloop" PATH=/usr/local/bin:/usr/bin:/bin \
	CLOOP_SECRET_KEY="$KEY" CLOOP_UI_TOKEN="$TOKEN" NO_COLOR=1 \
	"$BIN" ui --listen 127.0.0.1 --port "$PORT" --no-browser --projects "$PROJ" >"$ROOT/hub.log" 2>&1) &
hub_pid=$!
for _ in $(seq 60); do curl -fsS -o /dev/null "$API/healthz" 2>/dev/null && break; sleep 1; done
ssh -o BatchMode=yes -o ExitOnForwardFailure=yes -N -R "$PORT:127.0.0.1:$PORT" "$DEVICE" &
tunnel_pid=$!

say "the device: the cloop under test as $AGENT_USER, with a HOME that has no copilot"
remote "rm -rf $REMOTE && mkdir -p $REMOTE/bin $REMOTE/home $REMOTE/work"
scp -q "$BIN" "$DEVICE:$REMOTE/bin/cloop"
scp -q "$HERE/model.py" "$ROOT/bundle" "$DEVICE:$REMOTE/"
# The agent's PATH puts the cloop under test first: the hub dispatches the bare
# name `cloop run`, and the device's own /usr/local/bin/cloop is a release.
#
# Each background process is one simple command under `setsid`, its stdio off
# the channel: a compound one (`cd … && …`) is a subshell that holds the ssh
# channel open for as long as the process lives, and its PID is the subshell's.
# Here `$!` is the process itself, the leader of a session of its own, which
# teardown kills as a group.
DPATH=$REMOTE/bin:/usr/local/bin:/usr/bin:/bin
remote "chown -R $AGENT_USER: $REMOTE && chmod 0600 $REMOTE/bundle &&
	if runuser -u $AGENT_USER -- env -i HOME=$REMOTE/home PATH=$DPATH sh -c 'command -v copilot'; then
		echo 'copilot is already on the agent PATH; the install would not be exercised' >&2; exit 1; fi
	setsid nohup python3 $REMOTE/model.py $STUB_PORT $REMOTE/model.log </dev/null >$REMOTE/stub.out 2>&1 &
	echo \$! > $REMOTE/stub.pid
	setsid nohup runuser -u $AGENT_USER -- env -i HOME=$REMOTE/home PATH=$DPATH \
		$REMOTE/bin/cloop executor agent --token-file $REMOTE/bundle --credential $REMOTE/agent.json \
		--workdir-root $REMOTE/work </dev/null >$REMOTE/agent.log 2>&1 &
	echo \$! > $REMOTE/agent.pid"

executor=''
for _ in $(seq 90); do
	executor=$(api GET /api/executors | sed '$d' | python3 -c 'import json,sys
for e in json.load(sys.stdin).get("executors", []):
    if e.get("name") == "rig-copilot" and e.get("status") == "online": print(e["id"])' 2>/dev/null || true)
	[ -n "$executor" ] && break
	sleep 1
done
[ -n "$executor" ] || { echo "the device's agent never came online"; remote "tail -20 $REMOTE/agent.log"; exit 1; }
idx=$(api GET /api/projects | sed '$d' | python3 -c 'import json,sys
for i, p in enumerate(json.load(sys.stdin)["projects"]):
    if p["path"] == sys.argv[1]: print(i)' "$PROJ")
api POST "/api/projects/$idx/executor" "{\"executor_id\":\"$executor\"}" | tail -1 | grep -qx 200
echo "executor $executor online; project $idx bound to it"

say "1. auto-install off: the dispatch is refused, and the device is asked nothing"
refused=$(api POST "/api/projects/$idx/run" '{}')
echo "$refused" | head -c 900; echo
check "the run is refused with 409" grep -qx 409 <<<"$(echo "$refused" | tail -1)"
check "the refusal names copilot and the copilot image" \
	grep -q 'copilot.*cloop-harness-copilot' <<<"$refused"
sleep 2
check "the device was not asked to install anything" \
	bash -c "! ssh -o BatchMode=yes $DEVICE 'grep -q \"harness install\" $REMOTE/agent.log'"

say "2. auto-install on: the device installs copilot from GitHub's installer, then runs the task"
sed -i 's/auto_install_harness: false/auto_install_harness: true/' "$HUB/.cloop/config.yaml"
started=$(api POST "/api/projects/$idx/run" '{}')
echo "$started" | tail -1
status=''
for _ in $(seq 180); do
	status=$(api GET "/api/state?project_idx=$idx" | sed '$d' | python3 -c 'import json,sys
t = json.load(sys.stdin)["plan"]["tasks"][0]; print(t["status"])' 2>/dev/null || true)
	case "$status" in done | failed | skipped) break ;; esac
	sleep 2
done
echo "task 1: $status"
remote "grep 'harness install' $REMOTE/agent.log" || true
check "the task is done on the hub" test "$status" = done
check "the agent installed copilot into its user's ~/.local/bin" \
	remote "grep -q 'harness install: installed copilot at $REMOTE/home/.local/bin/copilot' $REMOTE/agent.log"
check "the installed CLI is GitHub's" \
	remote "runuser -u $AGENT_USER -- $REMOTE/home/.local/bin/copilot --version | grep -q 'GitHub Copilot CLI'"
check "the model was driven by the CLI's tool loop on the device" \
	remote "grep -q '\"tool_result\": \"written by copilot on the device' $REMOTE/model.log"
check "the hub records copilot in the device's inventory" \
	python3 -c 'import json,sys
for e in json.load(sys.stdin).get("executors", []):
    if e.get("name") == "rig-copilot" and "copilot" in (e.get("inventory") or {}).get("harnesses", []): sys.exit(0)
sys.exit(1)' < <(api GET /api/executors | sed '$d')

say "hub log (tail)"
tail -n 15 "$ROOT/hub.log" | cut -c1-240
say "agent log (tail)"
remote "tail -n 25 $REMOTE/agent.log" | cut -c1-240

if [ "$failures" -gt 0 ]; then echo "$failures check(s) failed"; exit 1; fi
echo "all checks passed"
