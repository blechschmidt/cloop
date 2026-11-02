#!/usr/bin/env bash
# requirements-check.sh — check cloop's own requirements, as CI's
# "cloop's own requirements hold" job does (Task 20466).
#
#   scripts/requirements-check.sh          # what `make requirements-check` runs
#
# .cloop/requirements.yaml holds the guarantees cloop's documentation makes
# — the hub runs no harness on its own host, every mutating route enforces
# RBAC, migrations stay additive, … — each with the existing test that proves
# it. This builds cloop from the checkout, lints the spec (an approved must
# requirement with no test is an error), and runs
#
#   cloop requirements check --file .cloop/requirements.yaml --json
#
# which runs every approved requirement's tests in the checkout, one after
# another, says on stderr what each found as it goes, prints the report framed
# at the end, and exits 1 when a requirement is unfulfilled or could not be
# checked. In CI the job's last step hands the step's output to
# scripts/ci-annotate, which annotates each failing requirement by its R-<n>
# on its line of the spec file; scripts/ci-why.sh reads them back.
#
# It runs hermetically, as the unit suite does:
#   - HOME is a fresh directory, removed afterwards, as internal/hometest's
#     Isolate makes it for a test binary: nothing the check or a test does
#     reads or writes the per-user state of whoever runs this;
#   - every CLOOP_* variable is unset — an agent running this inherits its
#     hub's CLOOP_SECRET_KEY, its task's attachments directory and more — as
#     is everything else hometest clears or that carries a credential: the
#     CLAUDE_*, ANTHROPIC_* and COPILOT_* variables, GH_TOKEN, GITHUB_TOKEN,
#     XDG_CONFIG_HOME and CREDENTIALS_DIRECTORY. The check itself gives each
#     test CLOOP_REQUIREMENT_ID and CLOOP_REQUIREMENT;
#   - Go's caches stay where they were: GOCACHE, GOMODCACHE, GOPATH and GOENV
#     are read before HOME moves, or every test would compile from nothing.
# tests/ciscripts holds this list to hometest's, and runs this script.
#
# Environment (read before any of it is cleared):
#   GO                        the go command (default: go)
#   REQUIREMENTS_SPEC         the spec file (default: .cloop/requirements.yaml)
#   REQUIREMENTS_CHECK_CLOOP  a cloop binary to run instead of building one
set -euo pipefail

cd "$(dirname "$0")/.."
go=${GO:-go}
spec=${REQUIREMENTS_SPEC:-.cloop/requirements.yaml}
cloop=${REQUIREMENTS_CHECK_CLOOP:-}

work=$(mktemp -d "${TMPDIR:-/tmp}/cloop-requirements.XXXXXX")
trap 'rm -rf "$work"' EXIT

# Go's own directories, while HOME still names the real one.
for v in GOCACHE GOMODCACHE GOPATH GOENV; do
	export "$v=$("$go" env "$v")"
done

if [ -z "$cloop" ]; then
	echo "==> building cloop from this checkout"
	"$go" build -o "$work/cloop" .
	cloop=$work/cloop
fi

# The environment the check, and every test it runs, starts from.
for name in $(compgen -e); do
	case $name in
	CLOOP_* | CLAUDE_* | ANTHROPIC_* | COPILOT_* | GH_TOKEN | GITHUB_TOKEN | XDG_CONFIG_HOME | CREDENTIALS_DIRECTORY)
		unset "$name"
		;;
	esac
done
mkdir "$work/home"
export HOME=$work/home USERPROFILE=$work/home

echo "==> cloop requirements lint --file $spec"
"$cloop" requirements lint --file "$spec"

echo "==> cloop requirements check --file $spec --json"
status=0
"$cloop" requirements check --file "$spec" --json || status=$?
exit "$status"
