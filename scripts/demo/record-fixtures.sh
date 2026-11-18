#!/usr/bin/env bash
# record-fixtures.sh — record the documentation site demo's fixtures
# (website/demo/fixtures) from a throwaway hub running three made-up projects.
#
#   scripts/demo/record-fixtures.sh            # record, write the fixtures, check the demo
#   KEEP=1 scripts/demo/record-fixtures.sh     # keep the scratch directory to look at
#
# What it does, and the traps, are in scripts/demo/README.md. In short: build
# cloop from this tree, start a hub with single sign-on against a made-up
# identity provider in a fresh directory under /tmp, create todo-api,
# landing-page and csv-report there, seed every admin surface through the
# hub's own API, run the projects for real (Claude Code and the Anthropic API
# are stood in for), then walk the real dashboard in headless Chrome as an
# administrator, fetch every other read the dashboard can make, scrub it all
# and write the fixtures.
#
# Isolation: every cloop command runs in the scratch directory or one of its
# projects — a cloop subcommand run from the repository's root opens and
# migrates the live database there — under `env -i` with its own HOME and
# CLOOP_HOME, so nothing inherited (CLOOP_SECRET_KEY and every other CLOOP_*,
# ANTHROPIC_*, CLAUDE_*, GITHUB_TOKEN) reaches it. The hub listens on
# 127.0.0.1 only. It stops only the processes it started, removes only its
# scratch directory, and makes no docker objects at all: the container
# executor it shows runs against a stand-in `docker`.
set -euo pipefail

REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
DEMO="$REPO/scripts/demo"
OUT="${OUT:-$REPO/website/demo/fixtures}"

say() { printf 'record-fixtures: %s\n' "$*" >&2; }
die() { say "$*"; exit 1; }

for tool in go git node python3 openssl curl ip; do
	command -v "$tool" >/dev/null || die "needs $tool on PATH"
done
node -e 'process.exit(Number(process.versions.node.split(".")[0]) >= 22 ? 0 : 1)' ||
	die "needs node 22 or later (walk.js uses its WebSocket)"
CHROME=${CHROME:-}
if [[ -z $CHROME ]]; then
	for c in /opt/cft/chrome-linux64/chrome "$(command -v google-chrome || true)" \
		"$(command -v chromium || true)" "$(command -v chromium-browser || true)"; do
		if [[ -n $c && -x $c ]]; then CHROME=$c; break; fi
	done
fi
[[ -n $CHROME ]] || die "no Chrome found; set CHROME to one"
# The hub runs in a PID namespace of its own: its health checks list every
# cloop run they can see, with its directory, and this machine's own runs must
# not end up in the demo.
unshare --pid --fork --mount-proc --kill-child true 2>/dev/null ||
	die "needs unshare --pid --fork --mount-proc (run as root): the hub must not see this machine's other processes"
free=$(df -Pm /tmp | awk 'NR == 2 {print $4}')
((free >= 3000)) || die "only ${free} MB free under /tmp; the recording needs about 3 GB"

# A private address of this machine for the fake Confluence and Jira: the
# knowledge connectors refuse loopback. docker0 or a bridge first, as the
# knowledge e2e test picks one.
PRIVATE_IP=${PRIVATE_IP:-}
if [[ -z $PRIVATE_IP ]]; then
	PRIVATE_IP=$(ip -4 -o addr show 2>/dev/null | awk '{split($4, a, "/"); print $2, a[1]}' |
		awk '$2 ~ /^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)/ {print ($1 ~ /^(docker|br-)/ ? 0 : 1), $2}' |
		sort -n | awk 'NR == 1 {print $2}')
fi
[[ -n $PRIVATE_IP ]] || die "no private IPv4 address on this machine for the fake Confluence and Jira; set PRIVATE_IP"

WORK=$(mktemp -d /tmp/cloop-demo-rec-XXXXXX)
chmod 700 "$WORK"
mkdir -p "$WORK"/{bin,home,cloophome,tmp,projects,fakes,logs}
# From here on nothing runs in the repository but `go build` and the demo's
# own build script.
cd "$WORK"

PIDS=()
cleanup() {
	set +e
	touch "$WORK/agent.stop"
	for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null; done
	# The runs the hub started, by their exact binary: only this recording's.
	ps -eo pid=,args= | awk -v bin="$WORK/bin/cloop" '$2 == bin {print $1}' | xargs -r kill 2>/dev/null
	sleep 1
	ps -eo pid=,args= | awk -v bin="$WORK/bin/cloop" '$2 == bin {print $1}' | xargs -r kill -9 2>/dev/null
	for pid in "${PIDS[@]}"; do wait "$pid" 2>/dev/null; done
	if [[ -n ${KEEP:-} ]]; then
		say "kept $WORK"
	else
		rm -rf "$WORK"
	fi
}
trap cleanup EXIT
trap 'exit 130' INT TERM

port() { python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])'; }

# The environment every process of the recording gets, and nothing else.
ENVV=(
	"HOME=$WORK/home" "CLOOP_HOME=$WORK/cloophome" "TMPDIR=$WORK/tmp"
	"PATH=$WORK/bin:/usr/local/bin:/usr/bin:/bin" "LANG=C.UTF-8" "TZ=UTC" "USER=demo" "LOGNAME=demo"
	"CLOOP_SECRET_KEY_FILE=$WORK/secret.key" "SSL_CERT_FILE=$WORK/fakes/ca.pem"
)
run() { env -i "${ENVV[@]}" "$@"; }
if run env | grep -Eq '^(CLOOP_SECRET_KEY|CLOOP_TASK_ID|CLOOP_UI_TOKEN|ANTHROPIC_|CLAUDE_|GITHUB_TOKEN|GH_TOKEN)='; then
	die "the isolated environment still carries an inherited credential"
fi

# A sealing key for the hub's secret store, made for this recording.
openssl rand -base64 48 | tr -d '\n' >"$WORK/secret.key"
chmod 600 "$WORK/secret.key"
TOKEN=$(openssl rand -hex 32)
printf '%s' "$TOKEN" >"$WORK/token"
chmod 600 "$WORK/token"
mkdir -p "$WORK/home/.claude"
printf '{"claudeAiOauth":{"accessToken":"demo-usage-token","refreshToken":"","expiresAt":0,"scopes":["user:inference","user:profile"]}}\n' \
	>"$WORK/home/.claude/.credentials.json"
printf '[user]\n\tname = Demo Developer\n\temail = dev@demo.example.com\n[init]\n\tdefaultBranch = main\n' >"$WORK/home/.gitconfig"
# Dana's own Claude login on a hub with single sign-on, in the per-person home
# the hub keeps (pkg/claudecodeauth: the first 32 hex digits of the sha256 of
# her e-mail address): what her limit views ask the fake usage endpoint with.
DANA_HOME="$WORK/home/.config/cloop/claude-identities/$(printf '%s' dana@demo.example.com | sha256sum | cut -c1-32)"
mkdir -p "$DANA_HOME"
chmod 700 "$WORK/home/.config/cloop/claude-identities" "$DANA_HOME"
cp "$WORK/home/.claude/.credentials.json" "$DANA_HOME/.credentials.json"

# The stand-ins: Claude Code, and a docker that answers the container
# executor's health checks and runs nothing.
cp "$DEMO/stub-claude.py" "$WORK/bin/claude"
cp "$DEMO/projects.py" "$WORK/bin/projects.py"
cat >"$WORK/bin/docker" <<'EOF'
#!/bin/sh
# The demo recording's docker: answers what the container executor asks to
# show itself healthy, and runs nothing.
case "$1" in
version) echo "27.5.1" ;;
info) case "$*" in *Runtimes*) echo '{"runc":{"path":"runc"},"runsc":{"path":"/usr/local/bin/runsc"}}' ;;
	*) echo "Server Version: 27.5.1" ;; esac ;;
image) [ "$2" = inspect ] && echo '[{"Id":"sha256:0000000000000000000000000000000000000000000000000000000000000000"}]' ;;
ps | network | volume) ;;
*) echo "docker: the demo recording runs no containers" >&2; exit 1 ;;
esac
EOF
chmod 755 "$WORK/bin/claude" "$WORK/bin/docker"

say "scratch directory $WORK; fake services on 127.0.0.1 and $PRIVATE_IP"
# (exec …) &, so that $! is the process itself and not a subshell that would
# outlive a kill of it.
(exec env -i "${ENVV[@]}" python3 "$DEMO/fakes.py" --work "$WORK/fakes" --projects-root "$WORK/projects" \
	--private-ip "$PRIVATE_IP" --ready "$WORK/fakes.json") >"$WORK/logs/fakes.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 1 100); do [[ -s $WORK/fakes.json ]] && break; sleep 0.2; done
[[ -s $WORK/fakes.json ]] || die "the fake services did not start: $(tail -5 "$WORK/logs/fakes.log")"
USAGE_URL=$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["usage"])' "$WORK/fakes.json")
IDP_URL=$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["idp"])' "$WORK/fakes.json")

# cloop from this tree, asking the fake for Claude's usage instead of
# api.anthropic.com; nothing else differs from a release build.
say "building cloop"
(cd "$REPO" && go build -ldflags "-X github.com/blechschmidt/cloop/pkg/ratelimit.usageEndpoint=$USAGE_URL" \
	-o "$WORK/bin/cloop" .)

PORT=$(port)
HUB="http://127.0.0.1:$PORT"
python3 - "$WORK" "$PORT" "$PRIVATE_IP" <<'EOF'
import datetime, json, os, socket, sys
work, port, ip = sys.argv[1], sys.argv[2], sys.argv[3]
fakes = json.load(open(os.path.join(work, "fakes.json")))
def hostport(url):
    return url.split("://", 1)[1].split("/", 1)[0]
state = {
    "started": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "hub_port": int(port),
    "cloop": os.path.join(work, "bin", "cloop"),
    "projects_root": os.path.join(work, "projects"),
    "fakes": fakes,
    "paths": {os.path.join(work, "projects"): "/home/demo/projects", os.path.join(work, "home"): "/home/demo",
              os.path.join(work, "cloophome"): "/home/demo/.cloop", os.path.join(work, "bin"): "/usr/local/bin",
              os.path.join(work, "tmp"): "/home/demo/tmp", work: "/home/demo/work"},
    "hosts": {f"http://127.0.0.1:{port}": "https://demo.example.com", f"127.0.0.1:{port}": "demo.example.com",
              f"ws://127.0.0.1:{port}": "wss://demo.example.com", f"localhost:{port}": "demo.example.com",
              fakes["idp"]: "https://login.demo.example.com",
              "https://" + hostport(fakes["wiki"]): "https://wiki.demo.example.com",
              "https://" + hostport(fakes["jira"]): "https://jira.demo.example.com",
              hostport(fakes["wiki"]): "wiki.demo.example.com", hostport(fakes["jira"]): "jira.demo.example.com",
              fakes["usage"].rsplit("/api/", 1)[0]: "https://api.anthropic.com",
              fakes["messages"].rsplit("/v1", 1)[0]: "https://api.anthropic.com",
              ip: "10.40.0.20", socket.gethostname(): "demo.example.com",
              # The hub's port was a free one picked at random: the demo's is 8080.
              f"config.ui-{port}.yaml": "config.ui-8080.yaml", f"port {port}": "port 8080"},
    "secrets": [open(os.path.join(work, "token")).read().strip(), open(os.path.join(work, "secret.key")).read().strip(),
                fakes["wiki_pat"], fakes["jira_pat"]],
}
json.dump(state, open(os.path.join(work, "state.json"), "w"), indent=1)
EOF

say "creating the projects"
run python3 "$DEMO/recorder.py" setup --state "$WORK/state.json"
TODO="$WORK/projects/todo-api"

# The hub's own settings, in the overlay for its port: single sign-on against
# the fake provider with a role policy, the container executor, and the hub's
# own directory (todo-api) freed from the per-host confinement that would
# otherwise refuse to run it.
cat >"$TODO/.cloop/config.ui-$PORT.yaml" <<EOF
ui:
  oidc:
    enabled: true
    issuer: $IDP_URL
    client_id: cloop-dashboard
    redirect_url: $HUB/auth/callback
    scopes: [openid, email, profile, groups]
    admin_emails: [dana@demo.example.com]
    default_role: none
    role_mappings:
      - {claim: group, value: platform-admins, role: admin}
      - {claim: group, value: maintainers, role: maintainer}
      - {claim: group, value: engineers, role: operator}
      - {claim: group, value: readers, role: viewer}
  auto_resume_on_cap_reset: false
executors:
  allow_host_process: true
  container:
    enabled: true
    id: sandbox-eu
    runtime: docker
    image: ghcr.io/blechschmidt/cloop-harness:latest
    network: bridge
    cpus: 2
    memory: 4g
    labels: {region: eu-central, tier: sandbox}
  host_sandbox:
    opt_out: [$TODO]
EOF

say "starting the hub on $HUB"
(cd "$TODO" && exec unshare --pid --fork --mount-proc --kill-child \
	env -i "${ENVV[@]}" "CLOOP_UI_TOKEN=$TOKEN" "$WORK/bin/cloop" ui --listen 127.0.0.1 \
	--port "$PORT" --no-browser --rate-limit 1000 --rate-burst 2000 \
	--projects "$WORK/projects/landing-page" --projects "$WORK/projects/csv-report") >"$WORK/logs/hub.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 1 150); do
	code=$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOKEN" "$HUB/api/version" || true)
	[[ $code == 200 ]] && break
	sleep 0.2
done
[[ $code == 200 ]] || die "the hub did not come up: $(tail -20 "$WORK/logs/hub.log")"

RECORDER=(run python3 "$DEMO/recorder.py")
HUBARGS=(--hub "$HUB" --token-file "$WORK/token" --state "$WORK/state.json")

say "enrolling the edge device"
(exec env -i "${ENVV[@]}" python3 "$DEMO/recorder.py" agent "${HUBARGS[@]}" --stop "$WORK/agent.stop" \
	--out "$WORK/device.json") >"$WORK/logs/agent.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 1 100); do [[ -s $WORK/device.json ]] && break; sleep 0.2; done
[[ -s $WORK/device.json ]] || die "the device did not enroll: $(tail -5 "$WORK/logs/agent.log")"
python3 - "$WORK" <<'EOF'
import json, os, sys
work = sys.argv[1]
state, dev = (json.load(open(os.path.join(work, f))) for f in ("state.json", "device.json"))
state["device"] = dev["device"]
state["secrets"] += [s for s in dev["secrets"] if s]
json.dump(state, open(os.path.join(work, "state.json"), "w"), indent=1)
EOF

say "seeding the admin surfaces"
"${RECORDER[@]}" seed "${HUBARGS[@]}" 2>&1 | tee "$WORK/logs/seed.log" >&2
say "running the projects (a few minutes)"
"${RECORDER[@]}" runs "${HUBARGS[@]}" 2>&1 | tee "$WORK/logs/runs.log" >&2

# The dashboard, walked as Dana, an administrator in every role's group.
curl -s -o /dev/null -X POST -H 'Content-Type: application/json' \
	-d '{"email":"dana@demo.example.com","name":"Dana Whitfield","groups":["platform-admins","maintainers","engineers","readers"]}' \
	"$IDP_URL/_identity"
python3 -c 'import json, sys; s = json.load(open(sys.argv[1])); json.dump([{"name": n, "path": p} for n, p in s["projects_by_name"].items()], open(sys.argv[2], "w"))' \
	"$WORK/state.json" "$WORK/projects.json"
say "walking the dashboard in headless Chrome"
env -i "${ENVV[@]}" node "$DEMO/walk.js" record "$CHROME" "$HUB" "" "$WORK/projects.json" "$WORK/walk.json" \
	2>&1 | tee "$WORK/logs/walk.log" >&2 || say "the walk reported problems; see above"

say "fetching every other read the dashboard can make"
"${RECORDER[@]}" crawl "${HUBARGS[@]}" --walk "$WORK/walk.json" --out "$WORK/crawl.json" 2>&1 | tee "$WORK/logs/crawl.log" >&2
say "scrubbing and writing $OUT"
"${RECORDER[@]}" write --state "$WORK/state.json" --crawl "$WORK/crawl.json" --out "$OUT" 2>&1 | tee -a "$WORK/logs/crawl.log" >&2

# The demo, built from the new fixtures and walked the same way.
say "building the demo and checking every tab"
python3 "$REPO/scripts/build-demo.py" --fixtures "$OUT" --out "$WORK/site/demo" >&2
SITE_PORT=$(port)
(exec python3 -m http.server -d "$WORK/site" --bind 127.0.0.1 "$SITE_PORT") >"$WORK/logs/site.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 1 50); do curl -sf -o /dev/null "http://127.0.0.1:$SITE_PORT/demo/" && break; sleep 0.2; done
python3 -c 'import json, sys; print(json.dumps([{"name": n, "path": "/home/demo/projects/" + n} for n in ("todo-api", "landing-page", "csv-report")]))' >"$WORK/demo-projects.json"
check=0
env -i "${ENVV[@]}" node "$DEMO/walk.js" check "$CHROME" "http://127.0.0.1:$SITE_PORT/demo" "$WORK/demo-projects.json" \
	"$WORK/check.json" 2>&1 | tee "$WORK/logs/check.log" >&2 || check=$?
python3 - "$WORK/check.json" <<'EOF' >&2
import json, sys
r = json.load(open(sys.argv[1]))
print(f"check: {len(r['tabs'])} tab visits, {len(r['unpopulated'])} without content, "
      f"{len(r['missing'])} requests without a fixture, {len(r['problems'])} page problems")
for t in r["unpopulated"]:
    print("  no content:", t)
for m in r["missing"]:
    print("  no fixture:", m)
for p in r["problems"][:20]:
    print("  problem:", p["kind"], p["text"][:200])
EOF
[[ $check == 0 ]] || say "the demo check found problems (above); the fixtures are written regardless"

# The gate CI runs on the fixtures: every dashboard read answered, nothing
# given away.
say "running tests/demo on the recording"
(cd "$REPO" && CLOOP_DEMO_FIXTURES="$OUT" go test -count=1 ./tests/demo/) >&2 ||
	say "tests/demo fails on this recording (above): fix the scrub or the crawl before committing it"
say "done: $(find "$OUT" -name '*.json' | wc -l) fixture files in $OUT"
