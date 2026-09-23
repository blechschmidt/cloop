#!/usr/bin/env bash
#
# demo-hub.sh — boot a throwaway cloop hub with demo projects, for screenshots.
#
# The screenshots in docs/screenshots/ are published. They must therefore
# contain no real project, no real goal and no real credential, which rules out
# pointing a camera at a working hub: a dashboard someone actually uses shows
# their work, and "I hid the private ones first" is a promise the next person
# regenerating the images has to remember to keep.
#
# So this builds a hub that has never seen any of that. Three invented projects
# in a temporary directory, a CLOOP_HOME of its own so the per-user project
# registry at ~/.cloop/projects.json is neither read nor written, and a port
# that is not the one anything else is on. Nothing it touches is shared with a
# real install, which is a property of the layout rather than of the care taken
# while running it.
#
# The states in the images are not written down anywhere. The hub runs
# `checkout-api` for real against the offline `mock` provider (see
# mock-responses.yaml) and is stopped partway, so the done tasks are done
# because cloop did them, the step log is a step log, and the durations are
# durations.
#
#   ./scripts/screenshots/demo-hub.sh up      # build, seed, run, leave it up
#   ./scripts/screenshots/demo-hub.sh down    # stop it and delete everything
#
# `up` prints the base URL on stdout. capture.js takes it from there.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
HERE="$ROOT/scripts/screenshots"

DEMO=${CLOOP_DEMO_DIR:-/tmp/cloop-screenshot-demo}
PORT=${CLOOP_DEMO_PORT:-8765}
GO=${GO:-go}
BASE="http://127.0.0.1:$PORT"

# The container executor needs an image that exists locally, or the Executors
# tab shows a preflight failure instead of the online executor the walkthrough
# describes. Override when the harness image is tagged differently.
HARNESS_IMAGE=${CLOOP_DEMO_IMAGE:-ghcr.io/blechschmidt/cloop-harness:latest}

export CLOOP_HOME="$DEMO/home"
BIN="$DEMO/cloop"
HUBDIR="$DEMO/projects/checkout-api"

# A HOME of its own, for the same reason as the CLOOP_HOME above but a
# different consumer. On the `claudecode` provider the Overview tab renders a
# Claude Code Subscription Caps card, and it fills that card by asking the
# `claude` CLI — which answers out of the *invoking user's* ~/.claude. Pointed
# at a real home, a demo hub photographs the operator's own subscription
# utilisation. Pointed here it finds no login, reports nothing, and the card
# stays empty, which is also what a fresh install looks like.
#
# CLAUDE_CONFIG_DIR has to go with it, and unsetting it is not optional: the
# CLI reads that variable *in preference to* HOME, so on any machine where it
# happens to be set — a cloop agent's own shell sets one — relocating HOME
# alone changes nothing and the card fills up regardless.
export HOME="$DEMO/fakehome"
unset CLAUDE_CONFIG_DIR

# ── helpers ─────────────────────────────────────────────────────────────────

api() { # api METHOD PATH [JSON]
  local method=$1 path=$2 body=${3:-}
  if [ -n "$body" ]; then
    curl -fsS -X "$method" -H 'Content-Type: application/json' -d "$body" "$BASE$path"
  else
    curl -fsS -X "$method" "$BASE$path"
  fi
}

# in PROJECT_DIR -- cmd...  runs a cloop subcommand inside a demo project.
in_project() {
  local dir=$1; shift
  (cd "$dir" && "$BIN" "$@")
}

wait_for_hub() {
  local i
  for i in $(seq 1 120); do
    curl -fsS "$BASE/healthz" >/dev/null 2>&1 && return 0
    sleep 0.5
  done
  echo "demo hub did not answer on $BASE" >&2
  tail -40 "$DEMO/hub.log" >&2 || true
  return 1
}

down() {
  # Match on the demo binary's own path rather than on a recorded pid. A pid
  # file is the obvious way and it was wrong here in a way that hid itself: a
  # surviving hub keeps answering on the port, wait_for_hub is satisfied by it,
  # and the capture photographs a control plane several iterations out of date
  # while every visible sign says it succeeded. The path cannot match anything
  # but this script's own processes, so there is nothing to be careful about.
  pkill -f "^$BIN " 2>/dev/null || true
  sleep 1
  pkill -9 -f "^$BIN " 2>/dev/null || true
  # Any sandbox the demo run left behind. Demo containers are named for the
  # demo hub's own executor id, so this cannot reach a real workload.
  if command -v docker >/dev/null 2>&1; then
    docker ps -aq --filter "label=cloop.demo=screenshots" 2>/dev/null \
      | xargs -r docker rm -f >/dev/null 2>&1 || true
  fi
  rm -rf "$DEMO"
}

# ── up ──────────────────────────────────────────────────────────────────────

up() {
  down

  mkdir -p "$DEMO/home" "$DEMO/projects" "$DEMO/fakehome"

  echo "==> building cloop into $BIN"
  (cd "$ROOT" && "$GO" build -o "$BIN" .)

  # Three projects, created by the CLI exactly as a first-time user would.
  echo "==> seeding projects"
  mkdir -p "$DEMO/projects/checkout-api" "$DEMO/projects/fleet-telemetry" "$DEMO/projects/docs-portal"

  in_project "$DEMO/projects/checkout-api" init --skip-clarify \
    --provider claudecode --model claude-opus-4-8 --effort high \
    --instructions "PCI-DSS scope. No cardholder data in logs or task results. Every schema change ships with a reversible migration." \
    "Ship an idempotent payment capture API with end-to-end audit coverage" >/dev/null
  in_project "$DEMO/projects/fleet-telemetry" init --skip-clarify \
    --provider claudecode --model claude-sonnet-4-6 --effort medium \
    "Collect metrics from field gateways over intermittent links and surface them in Grafana" >/dev/null
  in_project "$DEMO/projects/docs-portal" init --skip-clarify \
    --provider claudecode --model claude-sonnet-4-6 --effort medium \
    "Rebuild the customer documentation portal with versioned API references" >/dev/null

  in_project "$DEMO/projects/checkout-api"    plan import "$HERE/plan-checkout-api.yaml"    --replace --yes >/dev/null
  in_project "$DEMO/projects/fleet-telemetry" plan import "$HERE/plan-fleet-telemetry.yaml" --replace --yes >/dev/null
  in_project "$DEMO/projects/docs-portal"     plan import "$HERE/plan-docs-portal.yaml"     --replace --yes >/dev/null

  # The hub's own working directory is always listed as a project and cannot be
  # removed from the registry, so it has to *be* one of the demo projects
  # rather than a fourth directory that would show up empty in every shot.
  # That is also how a single user runs it: cd into the project, `cloop ui`.
  cat >"$HUBDIR/.cloop/config.yaml" <<YAML
executors:
  allow_host_process: true
  container:
    enabled: true
    runtime: docker
    image: $HARNESS_IMAGE
    cpus: 2
    memory: 2g
    pids_limit: 1024
    network: none
YAML
  chmod 600 "$HUBDIR/.cloop/config.yaml"

  # ── the real run that produces the states in the screenshots ──────────────
  #
  # Offline, deterministic, and deliberately stopped partway, so the plan is
  # caught mid-flight: the leading tasks done with the results the provider
  # actually returned, the rest still queued.
  #
  # `--steps` is the stop. It bounds this session only and is not persisted, so
  # the project is left with the unlimited step budget it really has rather
  # than with a cap invented for the photograph.
  echo "==> running checkout-api against the offline mock provider"
  cp "$HERE/mock-responses.yaml" "$HUBDIR/.cloop/mock_responses.yaml"
  ( cd "$HUBDIR" && timeout 120 \
      "$BIN" run --provider mock --steps "${CLOOP_DEMO_STEPS:-5}" --skip-clarify \
      >"$DEMO/run.log" 2>&1 ) || true
  rm -f "$HUBDIR/.cloop/mock_responses.yaml"

  # Hitting --steps parks the project at status=paused with the reason
  # "--steps limit of N reached" — a true statement about this capture harness
  # and a confusing one on a page teaching somebody the dashboard. Put the
  # project back to idle, which is what a plan that is part-done and not
  # currently running actually looks like. Nothing else the run wrote is
  # touched: the tasks, their results, the steps and the event history all
  # stay exactly as cloop left them.
  python3 - "$HUBDIR/.cloop/state.db" <<'PY'
import sqlite3, sys
db = sqlite3.connect(sys.argv[1])
db.execute("UPDATE metadata SET value='idle'  WHERE key='status'")
db.execute("UPDATE metadata SET value=''      WHERE key='pause_reason'")
db.commit()
db.close()
PY

  # ── the hub ───────────────────────────────────────────────────────────────
  echo "==> starting hub on $BASE"
  ( cd "$HUBDIR" && exec "$BIN" ui --port "$PORT" --no-browser \
      --projects "$DEMO/projects/fleet-telemetry" \
      --projects "$DEMO/projects/docs-portal" \
      >"$DEMO/hub.log" 2>&1 ) &
  wait_for_hub

  # `run --provider mock` pins the project to the provider it ran with, which
  # is an honest record of what happened and the wrong thing to photograph.
  # Set it back through the same endpoint the Overview tab's provider picker
  # uses, so the state is one the dashboard itself could have produced.
  api POST '/api/options/provider?project_idx=0' \
    '{"provider":"claudecode","model":"claude-opus-4-8","effort":"high"}' >/dev/null || true

  # Pin checkout-api to the container executor. A hub whose flagship project
  # runs as a child process of the control plane is the arrangement the rest of
  # these docs spend their time arguing against, and the Overview tab's
  # Executor card is where a reader looks to see which one is in force.
  api POST '/api/projects/0/executor' '{"executor_id":"container"}' >/dev/null || true

  # ── a real remote executor ────────────────────────────────────────────────
  #
  # Enrolled the way the docs say to enroll one — a single-use token, an agent
  # dialling out — so the Executors tab shows a genuine remote row with a
  # genuine build version rather than a fabricated one. It happens to be this
  # machine; nothing in the flow knows or cares.
  echo "==> enrolling a remote executor agent"
  if in_project "$HUBDIR" executor enroll --name edge-lab-01 \
       --label site=lab --label hardware=usb-serial \
       --server "ws://127.0.0.1:$PORT/api/executors/connect" \
       --bundle-file "$DEMO/enroll.json" >"$DEMO/enroll.log" 2>&1; then
    # --credential keeps the demo agent's identity inside $DEMO rather than at
    # ~/.cloop/agent.json, where it would overwrite the credential of a real
    # executor agent running on this machine.
    # --token-file, not --bundle: --bundle takes the cloopenroll1.… string
    # itself, and a bundle on a command line is a credential in `ps`.
    ( exec "$BIN" executor agent --token-file "$DEMO/enroll.json" \
        --credential "$DEMO/agent.json" --workdir-root "$DEMO/agent-work" \
        >"$DEMO/agent.log" 2>&1 ) &
    sleep 6
  else
    echo "    (enrollment failed; Executors will show host + container only)" >&2
    tail -5 "$DEMO/enroll.log" >&2 || true
  fi

  echo "$BASE"
}

case "${1:-up}" in
  up)   up ;;
  down) down; echo "demo hub removed" ;;
  *)    echo "usage: $0 [up|down]" >&2; exit 2 ;;
esac
