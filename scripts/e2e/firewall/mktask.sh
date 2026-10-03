#!/bin/sh
# Adds a firewall probe task to a project on a running hub (Task 20363).
#
#   CLOOP_HUB=http://127.0.0.1:18363 CLOOP_HUB_TOKEN=... \
#     ./mktask.sh <project_idx> <label> "1.1.1.1:443 1.0.0.1:443 …"
#
# The probe travels base64-encoded in the task description, on the line the
# stand-in harness (../gitproxy/claude) runs, so nothing is copied onto the
# device and the sandbox needs no Claude login.
set -eu
[ $# -eq 3 ] || { echo "usage: $0 <project_idx> <label> \"host:port ...\"" >&2; exit 2; }
idx=$1 label=$2 targets=$3
hub=${CLOOP_HUB:-http://127.0.0.1:18363}
here=$(cd "$(dirname "$0")" && pwd)
b64=$({ printf 'TARGETS="%s"\n' "$targets"; cat "$here/probe.sh"; } | base64 | tr -d '\n')
body=$(python3 -c 'import json,sys; print(json.dumps({"title": sys.argv[1], "description": sys.argv[2], "priority": 1}))' \
	"firewall probe: $label" \
	"Run the firewall probe in this sandbox and report every RESULT line.
E2E-SCRIPT-B64: $b64")
curl -fsS -X POST -H "Authorization: Bearer ${CLOOP_HUB_TOKEN:-}" -H 'Content-Type: application/json' \
	--data "$body" "$hub/api/tasks?project_idx=$idx" >/dev/null
echo "added firewall probe task ($label) to project $idx"
