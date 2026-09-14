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

# How to reach the proxy, as curl arguments. The URL always says :8443 because
# the certificate, the issuer and every redirect in the OIDC flow do; only the
# published host port is negotiable. Override both together when 8443 is taken:
#
#   CLOOP_EVAL_PORT=18443 \
#   CLOOP_EVAL_CURL_CONNECT='--connect-to cloop.localtest.me:8443:127.0.0.1:18443' \
#   make e2e-stack
read -r -a CURL_CONNECT <<<"${CLOOP_EVAL_CURL_CONNECT:---resolve cloop.localtest.me:8443:127.0.0.1}"
export CLOOP_EVAL_CURL_CONNECT

say()  { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
ok()   { printf '    \033[32m✔\033[0m %s\n' "$*"; }
die()  { printf '    \033[31m✗ %s\033[0m\n' "$*" >&2; exit 1; }

# sweep_exits — fail if any container's *final* state is a non-zero exit.
#
# The assertions above can all pass while a container died behind them: a
# one-shot that failed after its work was observed, a service that crashed once
# the last request was served, an OOM kill. None of that shows up in an exit
# code the script already collected, so it is asked for explicitly here.
#
# Judged on final state rather than on history, and that distinction is
# load-bearing. nginx resolves its upstream at config-parse time, so the proxy
# legitimately exits non-zero when it loses the start race against the hub and
# is restarted into a working state — documented in docker-compose.yml. Failing
# on "has ever exited non-zero" would make this gate red on a stack that is
# behaving exactly as designed, and a gate that cries wolf gets disabled.
#
# So: a container still running at teardown passes whatever it did on the way
# here, and a container that is *stopped* with a non-zero code fails. Restart
# counts are reported rather than asserted, because that is the signal that
# distinguishes "recovered once" from "crash-looping" for whoever reads the log.
sweep_exits() {
  local rc=0 id name state code restarts
  for id in $("${COMPOSE[@]}" ps -aq 2>/dev/null); do
    name=$(docker inspect -f '{{.Name}}' "$id" 2>/dev/null | sed 's|^/||')
    state=$(docker inspect -f '{{.State.Status}}' "$id" 2>/dev/null)
    code=$(docker inspect -f '{{.State.ExitCode}}' "$id" 2>/dev/null)
    restarts=$(docker inspect -f '{{.RestartCount}}' "$id" 2>/dev/null)
    [ -n "$name" ] || continue

    if [ "$state" = "running" ] || [ "$state" = "created" ]; then
      if [ "${restarts:-0}" -gt 0 ]; then
        printf '    \033[33m!\033[0m %s: running, but restarted %s time(s)\n' "$name" "$restarts"
      fi
      continue
    fi
    if [ "${code:-0}" -ne 0 ]; then
      rc=1
      printf '    \033[31m✗\033[0m %s exited %s (state %s) — last 80 lines:\n' "$name" "$code" "$state"
      docker logs --tail=80 "$id" 2>&1 | sed 's/^/        /' || true
    else
      printf '    \033[32m✔\033[0m %s exited 0\n' "$name"
    fi
  done
  return $rc
}

cleanup() {
  local status=$?
  # The cookie jars hold live session cookies and the CA is a temp copy; a
  # failure part-way through the SSO block would otherwise leave credentials in
  # /tmp. Unconditional, and first, so an early `die` cleans up too.
  rm -f "${ADMIN_JAR:-}" "${NOBODY_JAR:-}" "${CA_FILE:-}"

  # Runs before `down -v`, which destroys the evidence it reads.
  say "Container exit codes"
  if ! sweep_exits; then
    printf '    \033[31m✗ a container exited non-zero\033[0m\n' >&2
    # Only promotes a pass to a failure; never masks the original one. Spelled
    # as a full if rather than `[ ... ] && status=1`, whose non-zero status when
    # the test is false is a trap to reason about inside an EXIT handler.
    if [ $status -eq 0 ]; then status=1; fi
  fi

  if [ "$KEEP" = "1" ]; then
    say "KEEP=1: leaving the stack up. Tear down with: docker compose down -v"
    return $status
  fi
  say "Tearing down"
  # Logs before the containers go away: a failure here is otherwise
  # undiagnosable, because down -v destroys the only record of it.
  if [ $status -ne 0 ]; then
    "${COMPOSE[@]}" logs --no-color --tail=80 cloop executor enroll proxy dex 2>&1 | sed 's/^/    /' || true
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
       "${CURL_CONNECT[@]}" \
       "https://cloop.localtest.me:8443${path}" "$@"
}

# The same request as a single shell word, for wait_for, which takes a command
# rather than a function. Keeping one definition means the CA and the connection
# mapping cannot drift between the polled requests and the asserted ones.
hub_sh() {
  printf 'curl -sf --cacert %q' "$CA_FILE"
  local arg
  for arg in "${CURL_CONNECT[@]}"; do printf ' %q' "$arg"; done
  printf ' %q' "https://cloop.localtest.me:8443$1"
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

wait_for "hub is alive (/healthz)" 120 bash -c "$(hub_sh /healthz)"

say "The readiness gate: a hub with nothing to dispatch to must NOT be ready"
code=$(hub /readyz -o /dev/null -w '%{http_code}')
if [ "$code" != "503" ]; then
  die "/readyz returned $code, want 503 — a hub with nothing to dispatch to must not accept traffic"
fi
# Which gate it names is deliberately not asserted yet. Two are legitimately
# unsatisfied here and they resolve in a fixed order, identity first — and
# whether identity is satisfied at this instant is a race nobody wins reliably:
# the hub preflights its issuer before binding its listener, and that request
# goes through a proxy which compose only starts once the hub container exists.
# The executors gate is asserted precisely, below, once the SSO step has
# resolved the identity one and made the answer deterministic.
body=$(hub /readyz || true)
case "$body" in
  *'"status":"not_ready"'*) ok "/readyz is 503 and reports why" ;;
  *) die "/readyz is 503 but does not say why: $body" ;;
esac

# ── Single sign-on ──────────────────────────────────────────────────────────
#
# Everything else in this script authenticates with a PAT, which by design never
# touches the identity provider. So without the next three logins the entire SSO
# path — discovery, PKCE, the code exchange, ID-token verification, session
# minting and claim-to-role resolution — ships untested, and it is the first
# thing the documentation tells an operator to do.
say "SSO: signing in through dex, as three users with three different outcomes"

ADMIN_JAR=$(mktemp); NOBODY_JAR=$(mktemp)   # removed by cleanup(), on any exit

login() { CA_FILE="$CA_FILE" JAR_OUT="${2:-}" ./deploy/eval/oidc-login.sh "$1"; }

role_of() { printf '%s' "$1" | python3 -c 'import json,sys; print(json.load(sys.stdin)["role"])'; }

# The mapped admin: listed in ui.oidc.admin_emails.
admin_me=$(login admin@example.com "$ADMIN_JAR") || die "admin@example.com could not sign in"
[ "$(role_of "$admin_me")" = "admin" ] \
  || die "admin@example.com resolved to $(role_of "$admin_me"), want admin: $admin_me"
ok "admin@example.com signed in through dex and resolved to admin"

# The mapped operator: matched by a role_mapping on the email claim.
op_me=$(login operator@example.com) || die "operator@example.com could not sign in"
[ "$(role_of "$op_me")" = "operator" ] \
  || die "operator@example.com resolved to $(role_of "$op_me"), want operator: $op_me"
ok "operator@example.com mapped to operator by claim"

# The unmapped user. This is the one worth running: authentication *succeeds*
# and authority is still refused, because default_role is none. A hub that
# quietly handed this user viewer would pass every other assertion here.
nobody_me=$(login nobody@example.com "$NOBODY_JAR") || die "nobody@example.com could not sign in"
[ "$(role_of "$nobody_me")" = "none" ] \
  || die "SECURITY: nobody@example.com matches no mapping but resolved to \
$(role_of "$nobody_me"), not none — deny-by-default is not in force: $nobody_me"
ok "nobody@example.com authenticated and resolved to role none"

# Asserted against a real gated route, not just against /api/me. The first is
# the hub describing its decision; only this is the hub enforcing it.
code=$(hub /api/executors -b "$NOBODY_JAR" -o /dev/null -w '%{http_code}')
case "$code" in
  403|404) ok "an unmapped user is refused a gated route (HTTP $code)" ;;
  *) die "SECURITY: GET /api/executors returned $code for an unmapped user, want 403 — \
a user matching no role mapping must not read the fleet" ;;
esac

# And the contrast, so the 403 above cannot be explained by the route being
# broken for everyone.
code=$(hub /api/executors -b "$ADMIN_JAR" -o /dev/null -w '%{http_code}')
[ "$code" = "200" ] \
  || die "GET /api/executors returned $code for the admin session, want 200 — \
the deny above proves nothing if the route refuses everybody"
ok "the same route answers the admin session with 200"

# Now deterministic: the identity gate was satisfied by the logins above, so
# the only thing left keeping this hub out of service is the absence of an
# executor — which is the gate this stack exists to demonstrate.
say "With identity resolved, the remaining gate must be the executor one"
body=$(hub /readyz || true)
case "$body" in
  *executor*) ok "/readyz names executors as the one remaining reason" ;;
  *) die "/readyz should now be blocked only on executors, got: $body" ;;
esac

say "Enrolling the executor"
"${COMPOSE[@]}" up -d --build enroll executor
wait_for "the agent enrolled and connected (/readyz is green over the real TLS chain)" \
  "$TIMEOUT_SECS" bash -c "$(hub_sh /readyz)"

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
wait_for "hub back up after re-reading the registry" 120 bash -c "$(hub_sh /readyz)"

say "Minting a scoped API token for the run"
# Not the static CLOOP_UI_TOKEN: it passes the SSO gate but resolves to the
# default role, which this hub sets to "none". A PAT carries its own roles and
# is the designed path for non-interactive access.
TOKEN=$("${COMPOSE[@]}" run --rm --no-deps --entrypoint /usr/local/bin/cloop cloop \
  hub token create e2e --role admin --expires-in 1h --quiet | tr -d '\r\n')
[ -n "$TOKEN" ] || die "could not mint an API token"
ok "token minted"

AUTH=(-H "Authorization: Bearer $TOKEN")

say "Confirming the executor is registered, isolating, and schedulable"
# "A row exists" and "the scheduler would place work here" are different
# claims, and the gap between them is where this silently rots: an enrolled
# agent that is unreachable, cordoned or draining still appears in the fleet.
# /readyz went green above, so this asserts the specific node rather than the
# aggregate — a second executor could be carrying that readiness.
#
# Polled rather than read once: enrollment and the supervisor's first probe are
# separate events, so a node can be registered a moment before it is ready.
fleet_ready() {
  hub "/api/executors" "${AUTH[@]}" | python3 -c '
import json, sys
fleet = json.load(sys.stdin)
rows = fleet if isinstance(fleet, list) else fleet.get("executors", [])
for e in rows:
    if e.get("kind") != "remote":
        continue
    if e.get("sched_state") == "ready" and e.get("schedulable") is True:
        print("%s %s" % (e.get("name") or e.get("id"), e.get("sched_state")))
        sys.exit(0)
sys.exit(1)
'
}
wait_for "a remote executor reached a ready, schedulable state" 120 fleet_ready
ok "fleet reports: $(fleet_ready)"

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
