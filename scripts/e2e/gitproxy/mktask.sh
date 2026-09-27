#!/bin/sh
# Adds a git proxy probe task to a project on a running hub.
#
#   CLOOP_HUB=http://127.0.0.1:8080 CLOOP_HUB_TOKEN=... \
#     ./mktask.sh <project_idx> <scenario> <repo> <other_repo> [VAR=value ...]
#
# The probe travels base64-encoded in the task description, on a line the
# stand-in harness (./claude) looks for, so nothing has to be copied onto the
# device. STAMP defaults to the current UTC time; every branch the scenario
# needs defaults to a name under it, so a bare call is a complete run.
set -eu

[ $# -ge 4 ] || {
	echo "usage: $0 <project_idx> <branch|readonly|pat|ws> <repo> <other_repo> [VAR=value ...]" >&2
	exit 2
}
idx=$1 scenario=$2 repo=$3 other=$4
shift 4
hub=${CLOOP_HUB:-http://127.0.0.1:8080}
here=$(cd "$(dirname "$0")" && pwd)
stamp=$(date -u +%m%d%H%M%S)

case $scenario in
branch) defaults="ALLOWED=cloop/e2e-allowed-$stamp OTHER=cloop/e2e-other-$stamp OUTSIDE=e2e-outside-$stamp" ;;
readonly) defaults="RO_BRANCH=cloop/e2e-ro-$stamp" ;;
pat) defaults="PAT_BRANCH=cloop/e2e-pat-$stamp OUTSIDE=e2e-outside-$stamp" ;;
ws) defaults="WS_BRANCH=cloop/e2e-ws-$stamp OTHER=cloop/e2e-other-$stamp" ;;
*)
	echo "unknown scenario $scenario" >&2
	exit 2
	;;
esac

# Caller-supplied assignments come last, so they win over the defaults.
b64=$({
	printf 'SCENARIO=%s\nREPO=%s\nOTHER_REPO=%s\nSTAMP=%s\n' "$scenario" "$repo" "$other" "$stamp"
	for kv in $defaults "$@"; do printf '%s\n' "$kv"; done
	cat "$here/probe.sh"
} | base64 | tr -d '\n')

body=$(python3 -c 'import json,sys; print(json.dumps({"title": sys.argv[1], "description": sys.argv[2], "priority": 1}))' \
	"git proxy probe: $scenario $stamp" \
	"Run the git proxy probe ($scenario) in this sandbox and report every RESULT line.
E2E-SCRIPT-B64: $b64")

curl -fsS -X POST -H "Authorization: Bearer ${CLOOP_HUB_TOKEN:-}" -H 'Content-Type: application/json' \
	--data "$body" "$hub/api/tasks?project_idx=$idx" >/dev/null
echo "added probe task ($scenario, stamp $stamp) to project $idx"
