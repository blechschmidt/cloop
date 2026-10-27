#!/usr/bin/env bash
# run.sh — a device sandbox runs the digest of cloop's own image that the hub
# verified, and nothing the hub could not verify (Task 20453). See README.md
# for what each check proves.
#
#   scripts/e2e/image-provenance/run.sh            against the device `sgx`
#   DEVICE=edge-2 PORT=18470 scripts/e2e/image-provenance/run.sh
#
# Everything it starts is its own and is torn down on exit: a hub on this host
# (its own HOME, workdir, port and token, bound to loopback, cosign on its PATH),
# an `ssh -R` tunnel so the device's agent dials loopback, and on the device a
# second agent run as the production agent's user with a HOME of its own. The
# production agent and anything else on the device are left alone; the one
# thing it adds there is the pull of the signed image's digest, as the remedy of
# a refusal tells an operator to do.
#
# Environment: DEVICE (ssh host, default sgx), PORT (the hub, tunnelled; default
# 18470), AGENT_USER (default cloop-executor), SIGNED (an image of cloop's that
# carries the publishing workflow's signature; default
# ghcr.io/blechschmidt/cloop-harness:edge), UNSIGNED (one published before
# signing began; default ghcr.io/blechschmidt/cloop-harness:latest, as the
# device holds it), COSIGN (a cosign for the hub; default the one on PATH), BIN
# (a static build of the cloop under test; built if unset), KEEP=1.
set -euo pipefail

DEVICE=${DEVICE:-sgx}
PORT=${PORT:-18470}
AGENT_USER=${AGENT_USER:-cloop-executor}
SIGNED=${SIGNED:-ghcr.io/blechschmidt/cloop-harness:edge}
UNSIGNED=${UNSIGNED:-ghcr.io/blechschmidt/cloop-harness:latest}
COSIGN=${COSIGN:-$(command -v cosign || true)}
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../../.." && pwd)
ROOT=$(mktemp -d /tmp/cloop-image-provenance.XXXXXX)
REMOTE=/tmp/cloop-image-provenance-$PORT
HUB=$ROOT/hub PROJ=$ROOT/proj
TOKEN=$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')
KEY=$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')
API=http://127.0.0.1:$PORT
EDGE_PIN='^https://github\.com/blechschmidt/cloop/\.github/workflows/edge\.yml@refs/heads/main$'
hub_pid='' tunnel_pid='' failures=0

say() { printf '\n== %s\n' "$*"; }
check() { # check NAME COMMAND... — one PASS or FAIL line per claim
	local name=$1; shift
	if "$@"; then echo "PASS  $name"; else echo "FAIL  $name"; failures=$((failures + 1)); fi
}

[ -x "$COSIGN" ] || { echo "no cosign: set COSIGN to a cosign binary (the hub image bundles v3.1.4)"; exit 1; }
mkdir -p "$ROOT/bin" "$ROOT/home"
ln -s "$COSIGN" "$ROOT/bin/cosign"
HUBPATH=$ROOT/bin:/usr/local/bin:/usr/bin:/bin

# Every local cloop runs with an environment built here, never this shell's: a
# hub's child process inherits CLOOP_SECRET_KEY, and an override of the images
# pin in this shell would make the rig test something else.
local_cloop() { (cd "$1" && shift && env -i HOME="$ROOT/home" CLOOP_HOME="$ROOT/home/.cloop" \
	PATH="$HUBPATH" CLOOP_SECRET_KEY="$KEY" CLOOP_UI_TOKEN="$TOKEN" NO_COLOR=1 "$BIN" "$@"); }
api() { # api METHOD PATH [JSON] — prints the body, then the status on its own line
	curl -sS -X "$1" -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
		${3:+--data "$3"} -w '\n%{http_code}\n' "$API$2"
}
remote() { ssh -o BatchMode=yes "$DEVICE" "$@"; }

# start_hub [ENV=VALUE...] — the hub, with cosign on its PATH and the given
# extra environment; stop_hub ends it. The agent reconnects by itself.
start_hub() {
	(cd "$HUB" && exec env -i HOME="$ROOT/home" CLOOP_HOME="$ROOT/home/.cloop" PATH="$HUBPATH" \
		CLOOP_SECRET_KEY="$KEY" CLOOP_UI_TOKEN="$TOKEN" NO_COLOR=1 "$@" \
		"$BIN" ui --listen 127.0.0.1 --port "$PORT" --no-browser --projects "$PROJ" >>"$ROOT/hub.log" 2>&1) &
	hub_pid=$!
	for _ in $(seq 60); do curl -fsS -o /dev/null "$API/healthz" 2>/dev/null && return 0; sleep 1; done
	echo "the hub did not come up"; tail -20 "$ROOT/hub.log"; exit 1
}
stop_hub() { kill "$hub_pid" 2>/dev/null; wait "$hub_pid" 2>/dev/null || true; hub_pid=''; }

teardown() {
	set +e
	say "teardown"
	remote "f=$REMOTE/agent.pid; [ -f \$f ] && { kill -- -\$(cat \$f) 2>/dev/null || kill \$(cat \$f) 2>/dev/null; };
		sleep 1; [ '${KEEP:-}' = 1 ] || rm -rf $REMOTE" || true
	[ -n "$tunnel_pid" ] && kill "$tunnel_pid" 2>/dev/null
	[ -n "$hub_pid" ] && stop_hub
	if [ "${KEEP:-}" = 1 ]; then echo "kept $ROOT and $DEVICE:$REMOTE"; else rm -rf "$ROOT"; fi
}
trap teardown EXIT

if [ -z "${BIN:-}" ]; then
	say "building the cloop under test (static)"
	BIN=$ROOT/cloop
	(cd "$REPO" && CGO_ENABLED=0 go build -trimpath -o "$BIN" .)
fi
"$BIN" version | head -1
"$COSIGN" version 2>/dev/null | grep GitVersion || true

# The digest the registry serves for the signed tag now, asked independently
# of the hub: the one the hub must verify and the device must run.
digest_of() { docker buildx imagetools inspect "$1" | awk '/^Digest:/ { print $2; exit }'; }
repo_of() { echo "${1%:*}"; }
signed_digest=$(digest_of "$SIGNED")
unsigned_digest=$(digest_of "$UNSIGNED")
signed_ref="$(repo_of "$SIGNED")@$signed_digest"
echo "$SIGNED is $signed_digest; $UNSIGNED is $unsigned_digest"
check "the signed image verifies with the cloop under test" \
	env -i HOME="$ROOT/home" PATH="$HUBPATH" "$BIN" hub verify-image "$SIGNED"
check "the unsigned image is reported unsigned" \
	bash -c "env -i HOME='$ROOT/home' PATH='$HUBPATH' '$BIN' hub verify-image --json '$UNSIGNED' | grep -q '\"status\": \"unsigned\"'"

say "the hub: a mock project on a container-mode device, image_provenance: required"
mkdir -p "$HUB" "$PROJ"
local_cloop "$HUB" init --provider mock --skip-clarify "image provenance rig" >/dev/null
printf '\nexecutors:\n    image_provenance: required\n' >> "$HUB/.cloop/config.yaml"
local_cloop "$PROJ" init --provider mock --skip-clarify "Run in a verified image" >/dev/null
local_cloop "$PROJ" task add "Say hello from the sandbox" --no-ai --auto >/dev/null
local_cloop "$HUB" executor enroll --name rig-provenance --server "ws://127.0.0.1:$PORT/api/executors/connect" \
	--bundle-file "$ROOT/bundle" >/dev/null
start_hub
ssh -o BatchMode=yes -o ExitOnForwardFailure=yes -N -R "$PORT:127.0.0.1:$PORT" "$DEVICE" &
tunnel_pid=$!

say "the device: a second agent as $AGENT_USER, and the signed digest pulled"
remote "rm -rf $REMOTE && mkdir -p $REMOTE/bin $REMOTE/home $REMOTE/work"
scp -q "$BIN" "$DEVICE:$REMOTE/bin/cloop"
scp -q "$ROOT/bundle" "$DEVICE:$REMOTE/"
remote "docker pull -q $signed_ref >/dev/null && docker image inspect --format '{{.Id}}' $signed_ref"
DPATH=$REMOTE/bin:/usr/local/bin:/usr/bin:/bin
remote "chown -R $AGENT_USER: $REMOTE && chmod 0600 $REMOTE/bundle &&
	setsid nohup runuser -u $AGENT_USER -- env -i HOME=$REMOTE/home PATH=$DPATH \
		$REMOTE/bin/cloop executor agent --token-file $REMOTE/bundle --credential $REMOTE/agent.json \
		--workdir-root $REMOTE/work </dev/null >$REMOTE/agent.log 2>&1 &
	echo \$! > $REMOTE/agent.pid"

executor=''
for _ in $(seq 90); do
	executor=$(api GET /api/executors | sed '$d' | python3 -c 'import json,sys
for e in json.load(sys.stdin).get("executors", []):
    if e.get("name") == "rig-provenance" and e.get("status") == "online": print(e["id"])' 2>/dev/null || true)
	[ -n "$executor" ] && break
	sleep 1
done
[ -n "$executor" ] || { echo "the device's agent never came online"; remote "tail -20 $REMOTE/agent.log"; exit 1; }
idx=$(api GET /api/projects | sed '$d' | python3 -c 'import json,sys
for i, p in enumerate(json.load(sys.stdin)["projects"]):
    if p["path"] == sys.argv[1]: print(i)' "$PROJ")
api POST "/api/projects/$idx/executor" "{\"executor_id\":\"$executor\"}" | tail -1 | grep -qx 200
echo "executor $executor online; project $idx bound to it"

sandbox() { api PUT "/api/executors/$executor/sandbox" \
	"{\"mode\":\"container\",\"engine\":\"docker\",\"image\":\"$1\",\"network\":\"none\"}" | tail -1 | grep -qx 200; }
creates() { remote "docker events --since $1 --until \$(date +%s) --filter type=container --filter event=create \
	--format '{{.Actor.Attributes.image}}'"; }
# The newest task's status: each phase that needs a run of its own adds one.
task_status() { api GET "/api/state?project_idx=$idx" | sed '$d' | python3 -c 'import json,sys
print(json.load(sys.stdin)["plan"]["tasks"][-1]["status"])' 2>/dev/null || true; }
add_task() { local_cloop "$PROJ" task add "$1" --no-ai --auto >/dev/null; }
# The project's journal entries of one type, from its own database, read-only.
journal() { python3 -c 'import sqlite3,sys
db = sqlite3.connect("file:" + sys.argv[1] + "?mode=ro", uri=True)
for (m,) in db.execute("SELECT message FROM events WHERE type = ?", (sys.argv[2],)): print(m)' \
	"$PROJ/.cloop/state.db" "$1" 2>/dev/null || true; }
run_and_wait() {
	api POST "/api/projects/$idx/run" '{}' > "$ROOT/run.out"
	tail -1 "$ROOT/run.out"
	grep -qx 200 <(tail -1 "$ROOT/run.out") || return 0
	for _ in $(seq 120); do
		case "$(task_status)" in done | failed | skipped) break ;; esac
		sleep 2
	done
}

say "1. required, and the device's image unsigned: refused at the hub, the device asked nothing"
sandbox "$UNSIGNED"
since=$(remote date +%s)
run_and_wait
cat "$ROOT/run.out" | head -c 900; echo
check "the run is refused with 409" grep -qx 409 <(tail -1 "$ROOT/run.out")
check "the refusal is the provenance check's, naming the setting" \
	grep -q 'image-provenance.*image_provenance is required' "$ROOT/run.out"
check "no container was created on the device" test -z "$(creates "$since")"

say "2. required, and the device's image signed: the device runs the digest the hub verified"
sandbox "$SIGNED"
since=$(remote date +%s)
run_and_wait
echo "task 1: $(task_status)"
created=$(creates "$since")
echo "created on the device: $created"
check "the sandbox container on the device was created from the verified digest" \
	grep -qxF "$signed_ref" <<<"$created"
check "no container on the device was created from a tag" \
	bash -c "! grep -v '@sha256:' <<<'$created' | grep -q ."
check "the run's record names the verified digest" python3 -c 'import json,sys
r = json.load(open(sys.argv[1] + "/.cloop/sandbox-run.json"))
sys.exit(0 if r.get("image_provenance") == "verified" and r.get("verified_digest") == sys.argv[2]
         and r.get("pinned_image") == sys.argv[3] else 1)' "$PROJ" "$signed_digest" "$signed_ref"
check "the task is done on the hub" test "$(task_status)" = done

say "3. another identity's pin: the same signed image is wrongly signed, refused even under warn"
stop_hub
sed -i 's/image_provenance: required/image_provenance: warn/' "$HUB/.cloop/config.yaml"
start_hub CLOOP_PROVENANCE_IMAGES_IDENTITY="$EDGE_PIN"
for _ in $(seq 60); do
	api GET /api/executors | sed '$d' | grep -q '"status":"online"' && break; sleep 1
done
add_task "Say hello again"
since=$(remote date +%s)
run_and_wait
cat "$ROOT/run.out" | head -c 600; echo
check "the run is refused with 409" grep -qx 409 <(tail -1 "$ROOT/run.out")
check "the refusal says the signature is not the publishing workflow's" \
	grep -q 'not from the workflow that publishes them' "$ROOT/run.out"
check "no container was created on the device" test -z "$(creates "$since")"

say "4. warn, and the device's image unsigned: it runs the device's own copy, with the warning"
stop_hub
start_hub
for _ in $(seq 60); do
	api GET /api/executors | sed '$d' | grep -q '"status":"online"' && break; sleep 1
done
sandbox "$UNSIGNED"
since=$(remote date +%s)
run_and_wait
created=$(creates "$since")
echo "created on the device: $created"
check "the device ran its own copy of the tag" grep -qxF "$UNSIGNED" <<<"$created"
echo "journal: $(journal image_provenance | head -c 400)"
check "the run's journal carries the warning" grep -q "without a signature" <(journal image_provenance)
check "the task is done on the hub" test "$(task_status)" = done

say "hub log (provenance lines)"
grep -i 'provenance\|signature\|cosign' "$ROOT/hub.log" | tail -n 12 | cut -c1-260 || true
say "agent log (tail)"
remote "tail -n 15 $REMOTE/agent.log" | cut -c1-240

if [ "$failures" -gt 0 ]; then echo "$failures check(s) failed"; exit 1; fi
echo "all checks passed"
