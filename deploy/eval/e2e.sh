#!/usr/bin/env bash
# End-to-end test of the evaluation stack: bring it up, prove the readiness
# gate, enroll a remote executor, run one real task on it, tear it down.
#
# Invoked by `make e2e-stack`. Needs docker with the compose plugin, and a
# working outbound network for the image pulls.
#
# ── What this exists to prove ───────────────────────────────────────────────
#
# The compose stack used to bring up certs, dex, nginx and the hub — and no
# executor. With executors.allow_host_process: false that hub is correct and
# inert: it refuses host execution as designed and has nothing else to dispatch
# to, so the advertised evaluation stack could not execute a single task and
# deploy/README told the operator to "try POST /api/run and read the error".
#
# The sequence below is written so each step's failure is informative on its
# own, and so the strict-mode gate is *observed* rather than asserted from
# documentation: the hub is brought up alone first and /readyz must be red,
# then the executor enrolls and it must go green. A test that started
# everything at once would pass without ever demonstrating the mechanism.

set -euo pipefail

COMPOSE=(docker compose)
# The path the seed script clones the project into, inside the hub's volume.
HUB_PROJECT=/var/lib/cloop/projects/eval-project
KEEP=${KEEP:-0}
TIMEOUT_SECS=${TIMEOUT_SECS:-300}

say()  { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
ok()   { printf '    \033[32m✔\033[0m %s\n' "$*"; }
die()  { printf '    \033[31m✗ %s\033[0m\n' "$*" >&2; exit 1; }

cleanup() {
  local status=$?
  if [ "$KEEP" = "1" ]; then
    say "KEEP=1: leaving the stack up. Tear down with: docker compose down -v"
    return $status
  fi
  say "Tearing down"
  # Logs before the containers go away: a failure here is otherwise
  # undiagnosable, because down -v destroys the only record of it.
  if [ $status -ne 0 ]; then
    "${COMPOSE[@]}" logs --no-color --tail=80 cloop executor enroll 2>&1 | sed 's/^/    /' || true
  fi
  "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  return $status
}
trap cleanup EXIT

# hub <path> [curl args...] — request the hub through the proxy, over TLS,
# verifying the certificate the certs service generated.
#
# --resolve rather than --insecure: the certificate is valid for
# cloop.localtest.me, that name resolves to 127.0.0.1 in public DNS, and the
# test should fail if the hub ever serves a certificate that does not match.
# -k would hide exactly the class of bug `cloop hub doctor` reports.
hub() {
  local path=$1; shift
  curl --silent --show-error \
       --cacert "$CA_FILE" \
       --resolve "cloop.localtest.me:8443:127.0.0.1" \
       "https://cloop.localtest.me:8443${path}" "$@"
}

# wait_for <description> <seconds> <command...> — poll until the command
# succeeds, or fail with the description.
wait_for() {
  local what=$1 secs=$2; shift 2
  local deadline=$(( $(date +%s) + secs ))
  until "$@" >/dev/null 2>&1; do
    if [ "$(date +%s)" -ge "$deadline" ]; then
      die "timed out after ${secs}s waiting for: $what"
    fi
    sleep 2
  done
  ok "$what"
}

cd "$(dirname "$0")/../.."

say "Building images and starting the hub (no executor yet)"
"${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
"${COMPOSE[@]}" up -d --build certs dex cloop proxy

# The CA the certs service generated, so curl can verify rather than skip.
CA_FILE=$(mktemp)
trap 'rm -f "$CA_FILE"' RETURN 2>/dev/null || true
wait_for "certificate published" 120 \
  bash -c '"$0" cp certs:/certs/cert.pem "$1" 2>/dev/null || docker run --rm -v cloop-eval_certs:/certs alpine:3.20 cat /certs/cert.pem > "$1"' \
  docker "$CA_FILE"
[ -s "$CA_FILE" ] || die "could not read the generated certificate"

wait_for "hub is alive (/healthz)" 120 bash -c \
  'curl -sf --cacert "$0" --resolve cloop.localtest.me:8443:127.0.0.1 https://cloop.localtest.me:8443/healthz' "$CA_FILE"

say "The readiness gate: strict mode with no executor must be NOT ready"
code=$(hub /readyz -o /dev/null -w '%{http_code}')
if [ "$code" != "503" ]; then
  die "/readyz returned $code, want 503 — a hub with nothing to dispatch to must not accept traffic"
fi
body=$(hub /readyz || true)
case "$body" in
  *executor*) ok "/readyz is 503 and names executors as the reason" ;;
  *) die "/readyz is 503 but does not say why: $body" ;;
esac

say "Enrolling the executor"
"${COMPOSE[@]}" up -d --build enroll executor
wait_for "the agent enrolled and connected (/readyz is green)" "$TIMEOUT_SECS" bash -c \
  'curl -sf --cacert "$0" --resolve cloop.localtest.me:8443:127.0.0.1 https://cloop.localtest.me:8443/readyz' "$CA_FILE"

say "Seeding a project with an https origin the executor can fetch"
# As the agent user, not root: the service drops every capability, so a root
# process has no CAP_DAC_OVERRIDE and cannot write into the 65532-owned volumes
# anyway. Both mount points exist in the images owned by that uid, so a fresh
# volume is seeded writable.
"${COMPOSE[@]}" run --rm --no-deps \
  --entrypoint /bin/sh \
  -v "$(pwd)/deploy/eval/seed-project.sh:/seed.sh:ro" \
  -v cloop-eval_gitrepos:/srv/git \
  -v cloop-eval_state:/var/lib/cloop \
  executor /seed.sh
ok "project seeded"

# The hub caches its project registry; a restart is the supported way to make
# it re-read one that was written underneath it.
"${COMPOSE[@]}" restart cloop >/dev/null
wait_for "hub back up after re-reading the registry" 120 bash -c \
  'curl -sf --cacert "$0" --resolve cloop.localtest.me:8443:127.0.0.1 https://cloop.localtest.me:8443/readyz' "$CA_FILE"

say "Minting a scoped API token for the run"
# Not the static CLOOP_UI_TOKEN: it passes the SSO gate but resolves to the
# default role, which this hub sets to "none". A PAT carries its own roles and
# is the designed path for non-interactive access.
TOKEN=$("${COMPOSE[@]}" run --rm --no-deps --entrypoint /usr/local/bin/cloop cloop \
  hub token create e2e --role admin --expires-in 1h --quiet | tr -d '\r\n')
[ -n "$TOKEN" ] || die "could not mint an API token"
ok "token minted"

AUTH=(-H "Authorization: Bearer $TOKEN")

say "Confirming the executor is registered and isolating"
execs=$(hub "/api/executors" "${AUTH[@]}")
case "$execs" in
  *'"kind":"remote"'*) ok "a remote executor is registered" ;;
  *) die "no remote executor in /api/executors: $execs" ;;
esac

say "Locating the seeded project"
# Not project_idx=0: index 0 is always the hub's own working directory, and
# registry entries follow it. Resolving the index by path rather than assuming
# one means this keeps working if that ordering ever changes.
PROJECT_IDX=$(hub "/api/projects" "${AUTH[@]}" | python3 -c '
import json, sys
want = sys.argv[1]
for i, p in enumerate(json.load(sys.stdin).get("projects", [])):
    if p.get("path") == want:
        print(i); break
else:
    sys.exit(1)
' "$HUB_PROJECT") || die "the seeded project is not in /api/projects"
ok "project at index $PROJECT_IDX"

say "Dispatching one real task to the remote executor"
run_resp=$(hub "/api/run?project_idx=$PROJECT_IDX" "${AUTH[@]}" -X POST -H 'Content-Type: application/json' -d '{}')
case "$run_resp" in
  *error*) die "POST /api/run was refused: $run_resp" ;;
  *) ok "run accepted: $run_resp" ;;
esac

say "Asserting the workspace was provisioned on the device"
wait_for "the executor materialised the source tree (EVAL-MARKER present)" "$TIMEOUT_SECS" \
  "${COMPOSE[@]}" exec -T executor \
    sh -c 'find /var/lib/cloop-agent/work -name EVAL-MARKER -print -quit | grep -q .'

marker_path=$("${COMPOSE[@]}" exec -T executor \
  sh -c 'find /var/lib/cloop-agent/work -name EVAL-MARKER -print -quit' | tr -d '\r')
ok "workspace at $(dirname "$marker_path")"

# The tree came from the origin, not from a share of the hub's filesystem: the
# executor has no mount of the state volume at all, so its copy can only have
# been fetched.
"${COMPOSE[@]}" exec -T executor sh -c 'test ! -e /var/lib/cloop' \
  || die "the executor can see the hub's state volume — it is not isolated"
ok "the executor has no access to the hub's filesystem"

say "Asserting the result came back to the hub"
# The marker is emitted by the harness *on the device*, so finding it on the hub
# means the workload's output crossed the agent connection and was received —
# which is the round trip this stack exists to demonstrate. The hub echoes a
# dispatched run's stream to its own stderr and broadcasts it to dashboard
# clients, so its container log is where a script can observe it.
#
# What this deliberately does NOT claim: that the *files* the task changed came
# back. That is a separate mechanism (executor.WriteBack, a git bundle produced
# on the device and applied by pkg/writeback), and a run dispatched from
# POST /api/run does not currently request one — the task's own state stays on
# the device. Asserting otherwise here would make this script agree with a
# sentence rather than with the system.
wait_for "the harness ran on the device and its output reached the hub" "$TIMEOUT_SECS" bash -c '
  docker compose logs --no-color --since 10m cloop 2>/dev/null | grep -q CLOOP_E2E_TASK_EXECUTED
'

# And the same bytes on the device, so a passing assertion above cannot be
# explained by the hub having produced them itself.
"${COMPOSE[@]}" logs --no-color executor 2>/dev/null | grep -q "workspace for .* ready" \
  || die "the executor never reported provisioning a workspace"
ok "the executor's own log records the fetch"

say "PASSED"
printf '    The hub refused to be ready with nothing to dispatch to, an executor\n'
printf '    enrolled itself with a bootstrap token, a real task ran on it against a\n'
printf '    tree it fetched over https, and its output came back.\n'
