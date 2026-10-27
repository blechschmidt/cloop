#!/usr/bin/env bash
# ci-why.sh — why CI failed on a commit, read from a machine with no token.
#
#   scripts/ci-why.sh [REF]             why the push runs of REF (default HEAD) failed
#   scripts/ci-why.sh --job NAME [REF]  the annotations of the job NAME, passed or not
#
# For each push run of the commit it prints the run's verdict, and for each
# job that did not pass, the step that failed, a link to its log and the
# job's annotations. Those are what each CI job's last step writes when the
# job fails (scripts/ci-step.sh --why, Task 20444): one per failing test,
# panic, data race, timeout, build or vet failure — its package and test,
# where it points and its first lines — or a failed step's last lines.
#
# Why annotations: reading a job's log needs admin rights on the repository
# (GET .../actions/jobs/{id}/logs answers 403 without them), while a check
# run's annotations are public, and a job's id is its check run's.
#
# It uses GitHub's REST API without a token, which allows 60 requests an hour
# per address: one for the commit's runs, one for the jobs of each run that
# failed, one for the annotations of each job it prints — usually three or
# four, and one more to resolve a short SHA this clone does not have. It says
# how many are left. GITHUB_TOKEN, when set, is sent, and lifts the limit.
# CI_WHY_API and CI_WHY_REPO point it at another API or repository.
set -euo pipefail

api=${CI_WHY_API:-https://api.github.com}
repo=${CI_WHY_REPO:-blechschmidt/cloop}

usage() {
	sed -n '2,5p' "$0" | sed 's/^# \{0,1\}//'
}

job=
ref=
while [ $# -gt 0 ]; do
	case $1 in
	--job)
		[ $# -ge 2 ] || { usage >&2; exit 2; }
		job=$2
		shift 2
		;;
	-h | --help)
		usage
		exit 0
		;;
	-*)
		usage >&2
		exit 2
		;;
	*)
		[ -z "$ref" ] || { usage >&2; exit 2; }
		ref=$1
		shift
		;;
	esac
done
ref=${ref:-HEAD}

command -v curl > /dev/null || { echo "ci-why: needs curl" >&2; exit 1; }
command -v python3 > /dev/null || { echo "ci-why: needs python3" >&2; exit 1; }

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
requests=0

# header NAME is a header of the last response.
header() {
	tr -d '\r' < "$tmp/headers" | awk -v h="$1" 'tolower($1) == tolower(h) ":" { v = $2 } END { print v }'
}

# get PATH OUT fetches $api$PATH into OUT, or says why it could not and exits.
get() {
	requests=$((requests + 1))
	local code auth=()
	[ -z "${GITHUB_TOKEN:-}" ] || auth=(-H "Authorization: Bearer $GITHUB_TOKEN")
	if ! code=$(curl -sS -L --max-time 30 -o "$2" -D "$tmp/headers" -w '%{http_code}' \
		-H 'Accept: application/vnd.github+json' -H 'X-GitHub-Api-Version: 2022-11-28' \
		${auth[@]+"${auth[@]}"} "$api$1"); then
		echo "ci-why: GET $1 failed" >&2
		exit 1
	fi
	[ "$code" = 200 ] && return 0
	if [ "$(header x-ratelimit-remaining)" = 0 ]; then
		local reset
		reset=$(header x-ratelimit-reset)
		echo "ci-why: GitHub's $(header x-ratelimit-limit) requests an hour for this address are spent;" \
			"they come back at $(date -u -d "@${reset:-0}" '+%H:%M UTC' 2> /dev/null || echo "${reset:-?}")." \
			"A GITHUB_TOKEN lifts the limit." >&2
	else
		echo "ci-why: GET $1 answered $code: $(python3 -c 'import json, sys
try:
    print(json.load(open(sys.argv[1])).get("message", ""))
except Exception:
    print("")' "$2")" >&2
	fi
	exit 1
}

# The commit: resolved here when this clone has it, else by GitHub.
sha=$(git rev-parse --verify --quiet "$ref^{commit}" 2> /dev/null || true)
if [ -z "$sha" ]; then
	if [[ $ref =~ ^[0-9a-fA-F]{40}$ ]]; then
		sha=$ref
	elif [[ $ref =~ ^[0-9a-fA-F]{7,39}$ ]]; then
		get "/repos/$repo/commits/$ref" "$tmp/commit.json"
		sha=$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["sha"])' "$tmp/commit.json")
	else
		echo "ci-why: $ref is not a commit in this clone; name it by its SHA" >&2
		exit 1
	fi
fi

# report.py is the formatting: one subcommand per response.
cat > "$tmp/report.py" << 'PY'
import json, sys

def load(path):
    with open(path) as f:
        return json.load(f)

def runs(path):
    # One tab-separated line per run, for the shell to loop over.
    for r in load(path).get("workflow_runs", []):
        print("\t".join(str(r.get(k) or "-") for k in ("id", "name", "status", "conclusion", "html_url")))

def jobs(path, name):
    # One line per job to look at: every job that did not pass, or the one
    # named, with the steps that failed.
    for j in load(path).get("jobs", []):
        if name:
            if j.get("name") != name:
                continue
        elif j.get("conclusion") in ("success", "skipped", "neutral") or j.get("status") != "completed":
            continue
        failed = [s.get("name", "") for s in j.get("steps") or []
                  if s.get("conclusion") in ("failure", "timed_out", "cancelled")]
        print("\t".join([str(j.get("id")), j.get("name") or "-", j.get("status") or "-",
                         j.get("conclusion") or "-", j.get("html_url") or "-", " / ".join(failed) or "-"]))

def annotations(path):
    items = load(path)
    order = {"failure": 0, "warning": 1, "notice": 2}
    items.sort(key=lambda a: order.get(a.get("annotation_level"), 3))
    # GitHub adds this to every failed step; it says nothing the job's
    # verdict does not, once anything else explains the failure.
    boiler = lambda a: (a.get("message") or "").startswith("Process completed with exit code ")
    if any(a.get("annotation_level") == "failure" and not boiler(a) for a in items):
        items = [a for a in items if not boiler(a)]
    if not items:
        print("      (no annotations)")
    for a in items:
        level = {"failure": "error"}.get(a.get("annotation_level"), a.get("annotation_level") or "?")
        where = ""
        if a.get("path") and a.get("path") != ".github":
            where = "  " + a["path"] + (":%s" % a["start_line"] if a.get("start_line") else "")
        title = a.get("title") or ""
        lines = (a.get("message") or "").split("\n")
        if not title:
            title, lines = lines[0], lines[1:]
        print("      %-7s %s%s" % (level, title, where))
        for line in lines:
            print("              " + line)

cmd = sys.argv[1]
if cmd == "runs":
    runs(sys.argv[2])
elif cmd == "jobs":
    jobs(sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else "")
elif cmd == "annotations":
    annotations(sys.argv[2])
PY
report() { python3 "$tmp/report.py" "$@"; }

get "/repos/$repo/actions/runs?head_sha=$sha&event=push&per_page=100" "$tmp/runs.json"
report runs "$tmp/runs.json" > "$tmp/runs.tsv"
echo "$sha"
if [ ! -s "$tmp/runs.tsv" ]; then
	echo "  no push runs: not pushed yet, or GitHub has not started them"
fi
shown=0
while IFS=$'\t' read -r id name status conclusion url; do
	verdict=$conclusion
	[ "$status" = completed ] || verdict=$status
	echo "  $name: $verdict  $url"
	if [ -z "$job" ]; then
		case $conclusion in success | skipped | neutral) continue ;; esac
	fi
	get "/repos/$repo/actions/runs/$id/jobs?filter=latest&per_page=100" "$tmp/jobs-$id.json"
	report jobs "$tmp/jobs-$id.json" "$job" > "$tmp/jobs-$id.tsv"
	while IFS=$'\t' read -r jid jname jstatus jconclusion jurl jsteps; do
		shown=$((shown + 1))
		jverdict=$jconclusion
		[ "$jstatus" = completed ] || jverdict=$jstatus
		echo "    $jname: $jverdict"
		[ "$jsteps" = - ] || echo "      failed at: $jsteps"
		echo "      $jurl"
		get "/repos/$repo/check-runs/$jid/annotations?per_page=100" "$tmp/annotations-$jid.json"
		report annotations "$tmp/annotations-$jid.json"
	done < "$tmp/jobs-$id.tsv"
done < "$tmp/runs.tsv"
if [ -n "$job" ] && [ "$shown" = 0 ]; then
	echo "  no job named \"$job\" in these runs"
fi
left=$(header x-ratelimit-remaining)
echo "($requests request(s) to GitHub; ${left:-unknown} left this hour)"
