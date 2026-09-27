#!/bin/sh
# Git proxy probe (Task 20346). Runs INSIDE a sandbox that holds a guarded
# GitHub lease — the workload's own view of the git interception proxy.
#
# mktask.sh prepends the parameters as shell assignments:
#   SCENARIO    branch | readonly | pat | ws
#   REPO        owner/name the project was granted
#   OTHER_REPO  owner/name the same credential can reach but the grant does not name
#   STAMP       unique suffix for every branch this run creates
#   branch:   ALLOWED (inside the grant's branch list), OTHER (inside the hub's
#             allowlist, outside the grant's), OUTSIDE (outside the hub's)
#   readonly: RO_BRANCH, VICTIM (an existing scratch branch the probe tries to delete)
#   pat:      PAT_BRANCH, OUTSIDE
#   ws:       WS_BRANCH, OTHER
#
# Every check prints one line, "RESULT <id> PASS|FAIL <detail>", and the run
# ends with SUMMARY. Nothing here prints a credential: the token checks report
# where a token was found, never its value. See README.md for the catalogue.
set -u
: "${SCENARIO:?}" "${REPO:?}" "${OTHER_REPO:?}" "${STAMP:?}"

pass=0
fail=0
res() {
	printf 'RESULT %s %s %s\n' "$1" "$2" "$3"
	if [ "$2" = PASS ]; then pass=$((pass + 1)); else fail=$((fail + 1)); fi
}
info() { printf 'INFO %s\n' "$*"; }
# brief renders the lines of a git transcript that say what happened, as one line.
brief() {
	grep -E 'remote:|error:|fatal:|rejected|\[new|->|denied|refused|not found|returned error|admit' "$1" |
		tr -s ' \t' ' ' | tail -n 3 | tr '\n' ' ' | cut -c1-360
}

# network_failure: git never got an HTTP answer at all.
network_failure() { [ ! -s "$1" ] || grep -Eq 'Could not resolve host|Failed to connect|Connection timed out|Connection refused|Network is unreachable|SSL|certificate' "$1"; }
# by_proxy: the refusal came from cloop's git proxy — its own error body, or a
# receive-pack report naming the ref it rejected.
by_proxy() { grep -Eq 'cloop git proxy|remote rejected|\(ref update denied|session may not' "$1"; }

GH=https://github.com
BASE=$(pwd)
W=$BASE/e2e-$STAMP
rm -rf "$W"
mkdir -p "$W" && cd "$W" || { res SETUP FAIL "cannot create $W"; exit 1; }
O=$W/out.txt
export GIT_TERMINAL_PROMPT=0
GITC="git -c user.name=cloop-e2e -c user.email=cloop-e2e@example.invalid -c commit.gpgsign=false"

info "scenario=$SCENARIO repo=$REPO other=$OTHER_REPO stamp=$STAMP"
info "id=$(id) host=$(hostname) kernel=$(uname -r)"
if [ -f /.dockerenv ]; then info "sandbox=container(/.dockerenv)"; else info "sandbox=no /.dockerenv"; fi
info "dmesg_head=$(dmesg 2>/dev/null | head -n 1 | cut -c1-80)"
info "git=$(git --version) cwd=$BASE"
info "lease_dir=${CLOOP_LEASE_DIR:-unset} git_config_global=${GIT_CONFIG_GLOBAL:-unset}"
info "proxy_url=${CLOOP_GIT_PROXY_URL:-unset} mode=${CLOOP_GIT_PROXY_MODE:-unset} push_refs=${CLOOP_GIT_PUSH_REFS:-unset} push_branches=${CLOOP_GITHUB_PUSH_BRANCHES:-unset}"
info "allowlist=${CLOOP_GITHUB_REPO_ALLOWLIST:-unset} perms=${CLOOP_GITHUB_PERMISSIONS:-unset} withheld=${CLOOP_GITHUB_WRITE_WITHHELD:-unset}"
if [ -n "${CLOOP_LEASE_DIR:-}" ]; then
	info "lease_files=$(ls -la "$CLOOP_LEASE_DIR" 2>&1 | awk 'NR>1 && $NF!="." && $NF!=".." {print $1" "$NF}' | tr '\n' ';')"
fi
info "rewrites=$(git config --global --get-regexp '^url\..*\.insteadof$' 2>&1 | tr '\n' ';')"

# ── Token isolation ─────────────────────────────────────────────────────
# Both GitHub token generations: the classic ghs_<36 alnum> and the long
# ghs_<id>_<...>.<...>.<...> installation tokens, which contain '.' and '_'.
TOKRE='(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_.]{20,}|github_pat_[A-Za-z0-9_]{20,}'
leak=""
env | grep -Eq "$TOKRE" && leak="$leak env"
[ -n "${CLOOP_LEASE_DIR:-}" ] && grep -rEqs "$TOKRE" "$CLOOP_LEASE_DIR" && leak="$leak lease-dir"
grep -rEqs "$TOKRE" "$BASE/.cloop" 2>/dev/null && leak="$leak project-state"
if [ -z "$leak" ]; then
	res T1 PASS "no GitHub-issued token in the environment, the lease directory or the project state"
else
	res T1 FAIL "a GitHub-issued token is readable in:$leak"
fi

CRED=${CLOOP_LEASE_DIR:-/nonexistent}/git-proxy-credential
SUSER=$(sed -n 's/^username=//p' "$CRED" 2>/dev/null)
SPASS=$(sed -n 's/^password=//p' "$CRED" 2>/dev/null)
if [ -n "$SPASS" ]; then
	info "session=$SUSER token_chars=${#SPASS}"
	# T2: the session token presented to github.com itself, bypassing the proxy.
	HDR="Authorization: Basic $(printf '%s:%s' "$SUSER" "$SPASS" | base64 | tr -d '\n')"
	# Bounded: a firewall that drops rather than rejects would hold each
	# attempt for the kernel's full SYN retry budget (over two minutes).
	if timeout 20 env GIT_CONFIG_GLOBAL=/dev/null git -c credential.helper= -c "http.extraHeader=$HDR" \
		ls-remote "$GH/$REPO" >"$O" 2>&1; then
		res T2 FAIL "github.com accepted the proxy session token directly"
	elif network_failure "$O"; then
		res T2 PASS "github.com is unreachable from this sandbox, so the session token cannot be tried there: $(brief "$O")"
	else
		res T2 PASS "github.com itself rejects the session token: $(brief "$O")"
	fi
else
	res T2 FAIL "no proxy session credential in the lease directory"
fi

# T3: without the lease's git config there is no credential at all.
if timeout 20 env GIT_CONFIG_GLOBAL=/dev/null git -c credential.helper= ls-remote "$GH/$REPO" >"$O" 2>&1; then
	res T3 FAIL "private $REPO is readable without going through the proxy"
elif network_failure "$O"; then
	res T3 PASS "github.com is unreachable from this sandbox except through the proxy: $(brief "$O")"
else
	res T3 PASS "github.com refuses the sandbox without the proxy (no credential of its own): $(brief "$O")"
fi

# ── Per-repository restriction ──────────────────────────────────────────
if git clone -q "$GH/$REPO" repo >"$O" 2>&1; then
	res P1 PASS "cloned $GH/$REPO through $(git -C repo ls-remote --get-url origin)"
else
	res P1 FAIL "clone of the granted $REPO failed: $(brief "$O")"
	printf 'SUMMARY %s pass=%d fail=%d (clone failed; nothing further to test)\n' "$SCENARIO" "$pass" "$fail"
	cd "$BASE" && rm -rf "$W"
	exit 0
fi

if git ls-remote "$GH/$OTHER_REPO" >"$O" 2>&1; then
	res P2 FAIL "$OTHER_REPO is readable through this session"
else
	if by_proxy "$O"; then res P2 PASS "$OTHER_REPO refused by the proxy: $(brief "$O")"; else res P2 FAIL "$OTHER_REPO refused, but not by the proxy: $(brief "$O")"; fi
fi
if git clone -q "$GH/$OTHER_REPO" other >"$O" 2>&1; then
	res P3 FAIL "cloned $OTHER_REPO"
else
	if by_proxy "$O"; then res P3 PASS "clone of $OTHER_REPO refused by the proxy: $(brief "$O")"; else res P3 FAIL "clone of $OTHER_REPO refused, but not by the proxy: $(brief "$O")"; fi
fi
if git -C repo push "$GH/$OTHER_REPO" "HEAD:refs/heads/cloop/e2e-cross-$STAMP" >"$O" 2>&1; then
	res P4 FAIL "pushed into $OTHER_REPO"
else
	if by_proxy "$O"; then res P4 PASS "push into $OTHER_REPO refused by the proxy: $(brief "$O")"; else res P4 FAIL "push into $OTHER_REPO refused, but not by the proxy: $(brief "$O")"; fi
fi
OWNER=${OTHER_REPO%%/*}
NAME=${OTHER_REPO#*/}
n=0
for u in "$GH/$OWNER%2F$NAME" "$GH/$OWNER/..%252F$NAME" "$GH/$OTHER_REPO.git.git" \
	"$GH/$(printf '%s' "$OTHER_REPO" | tr 'a-z' 'A-Z')" "$GH/$REPO/../$NAME"; do
	n=$((n + 1))
	if git ls-remote "$u" >"$O" 2>&1 && grep -q 'refs/heads' "$O"; then
		res "P5.$n" FAIL "path variant $u reached a repository: $(head -c 120 "$O")"
	else
		if by_proxy "$O"; then how="by the proxy"; elif network_failure "$O"; then how="NETWORK FAILURE, inconclusive"; else how="by the git client"; fi
		case $how in NETWORK*) res "P5.$n" FAIL "path variant ${u#"$GH"/}: $how: $(brief "$O")" ;; *) res "P5.$n" PASS "path variant ${u#"$GH"/} refused $how" ;; esac
	fi
done
if git ls-remote "$GH/$(printf '%s' "$REPO" | tr 'a-z' 'A-Z')" refs/heads/main >"$O" 2>&1 && grep -q refs/heads/main "$O"; then
	info "case variant of the granted repo is admitted (GitHub paths are case-insensitive)"
else
	info "case variant of the granted repo: $(brief "$O")"
fi

# ── Pushes ──────────────────────────────────────────────────────────────
cd repo || exit 1
printf 'Task 20346 git proxy e2e %s (%s)\n' "$STAMP" "$SCENARIO" >"t20346-$STAMP.txt"
git add "t20346-$STAMP.txt" && $GITC commit -qm "Task 20346 git proxy e2e $STAMP ($SCENARIO)" >/dev/null
LOCAL=$(git rev-parse HEAD)
MAIN0=$(git ls-remote origin refs/heads/main | cut -f1)
info "main=$MAIN0 local=$LOCAL"
remote_sha() { git ls-remote origin "$1" 2>/dev/null | cut -f1; }
push() { git push origin "$@" >"$O" 2>&1; }

# expect_denied ID REF DESCRIPTION [push args...]: the push must fail and the
# ref must end where it started.
expect_denied() {
	id=$1 ref=$2 what=$3
	shift 3
	before=$(remote_sha "$ref")
	if push "$@"; then
		res "$id" FAIL "$what was ACCEPTED: $(brief "$O")"
	elif [ "$(remote_sha "$ref")" != "$before" ]; then
		res "$id" FAIL "$what reported failure but $ref moved"
	elif ! by_proxy "$O"; then
		res "$id" FAIL "$what failed, but not with a proxy refusal: $(brief "$O")"
	else
		res "$id" PASS "$what refused: $(brief "$O")"
	fi
}
expect_allowed() {
	id=$1 ref=$2 what=$3
	shift 3
	if push "$@" && [ "$(remote_sha "$ref")" = "$(git rev-parse HEAD)" ]; then
		res "$id" PASS "$what accepted, $ref is at $(git rev-parse --short HEAD) on GitHub"
	else
		res "$id" FAIL "$what: $(brief "$O")"
	fi
}

case $SCENARIO in
branch)
	expect_allowed B1 "refs/heads/$ALLOWED" "push to $ALLOWED (inside the grant's branches)" "HEAD:refs/heads/$ALLOWED"
	expect_denied B2 "refs/heads/$OTHER" "push to $OTHER (inside the hub's cloop/**, outside the grant)" "HEAD:refs/heads/$OTHER"
	expect_denied B3 refs/heads/main "push to main" HEAD:refs/heads/main
	expect_denied B4 "refs/heads/$OUTSIDE" "push to $OUTSIDE (outside the hub's allowlist)" "HEAD:refs/heads/$OUTSIDE"
	expect_denied B5 "refs/heads/$ALLOWED" "delete of $ALLOWED" ":refs/heads/$ALLOWED"
	expect_denied B6 "refs/heads/$ALLOWED-2" "one push carrying $ALLOWED-2 and main" \
		"HEAD:refs/heads/$ALLOWED-2" HEAD:refs/heads/main
	git tag "e2e-$STAMP"
	expect_denied B7 "refs/tags/e2e-$STAMP" "push of tag e2e-$STAMP" "refs/tags/e2e-$STAMP"
	printf 'second commit\n' >>"t20346-$STAMP.txt"
	$GITC commit -qam "Task 20346 second commit" >/dev/null
	expect_allowed B8 "refs/heads/$ALLOWED" "fast-forward update of $ALLOWED" "HEAD:refs/heads/$ALLOWED"
	;;
readonly)
	if git fetch -q origin >"$O" 2>&1; then res R1 PASS "fetch allowed"; else res R1 FAIL "fetch: $(brief "$O")"; fi
	expect_denied R2 "refs/heads/$RO_BRANCH" "push to $RO_BRANCH (inside the hub's cloop/**)" "HEAD:refs/heads/$RO_BRANCH"
	expect_denied R3 refs/heads/main "push to main" HEAD:refs/heads/main
	expect_denied R4 "refs/heads/$VICTIM" "delete of $VICTIM (a scratch branch that exists)" ":refs/heads/$VICTIM"
	if [ "${CLOOP_GIT_PROXY_MODE:-}" = read-only ] && [ -z "${CLOOP_GIT_PUSH_REFS:-}" ]; then
		res R5 PASS "the lease announces read-only and no push refs"
	else
		res R5 FAIL "lease announces mode=${CLOOP_GIT_PROXY_MODE:-unset} push_refs=${CLOOP_GIT_PUSH_REFS:-unset}"
	fi
	;;
pat)
	expect_allowed W1 "refs/heads/$PAT_BRANCH" "push to $PAT_BRANCH (inside the hub's cloop/**)" "HEAD:refs/heads/$PAT_BRANCH"
	expect_denied W2 refs/heads/main "push to main" HEAD:refs/heads/main
	expect_denied W3 "refs/heads/$OUTSIDE" "push to $OUTSIDE (outside the hub's allowlist)" "HEAD:refs/heads/$OUTSIDE"
	;;
ws)
	# The working directory is the project's own repository, provisioned by the
	# device (not the sandbox) through a proxy session pinned to it.
	if git -C "$BASE" rev-parse --git-dir >/dev/null 2>&1; then
		WSURL=$(git -C "$BASE" config --get remote.origin.url)
		WSHEAD=$(git -C "$BASE" rev-parse HEAD)
		if [ "$WSHEAD" = "$MAIN0" ]; then
			res WS1 PASS "the workspace is a checkout of $REPO at main ($(git -C "$BASE" rev-parse --short HEAD)), origin $WSURL"
		else
			res WS1 FAIL "the workspace HEAD $WSHEAD is not $REPO main $MAIN0"
		fi
		case $WSURL in
		*"${CLOOP_GIT_PROXY_URL:-no-proxy-url}"*) res WS2 PASS "the provisioned origin is the proxy, not the forge" ;;
		*) res WS2 FAIL "the provisioned origin is $WSURL" ;;
		esac
		if grep -Eqs "$TOKRE" "$BASE/.git/config" || grep -qis 'extraheader' "$BASE/.git/config"; then
			res WS3 FAIL "the workspace's .git/config holds a credential"
		else
			res WS3 PASS "no credential in the workspace's .git/config"
		fi
		# Pushing from the provisioned checkout itself, by its own origin: git asks
		# the lease's helper, which answers for the proxy host with the lease's
		# session, so the grant's branch list applies here too. A new commit
		# first, so that both pushes below carry a real ref update: pushing the
		# provisioned HEAD to main would be a no-op git never sends.
		printf 'workspace commit %s\n' "$STAMP" >"$BASE/t20346-ws-$STAMP.txt"
		git -C "$BASE" add "t20346-ws-$STAMP.txt" &&
			$GITC -C "$BASE" commit -qm "Task 20346 workspace commit $STAMP" >/dev/null
		WSHEAD=$(git -C "$BASE" rev-parse HEAD)
		if (cd "$BASE" && git push origin "HEAD:refs/heads/$WS_BRANCH-b" >"$O" 2>&1) &&
			[ "$(remote_sha "refs/heads/$WS_BRANCH-b")" = "$WSHEAD" ]; then
			res WS4 PASS "push from the workspace to $WS_BRANCH-b accepted"
		else
			res WS4 FAIL "push from the workspace to $WS_BRANCH-b: $(brief "$O")"
		fi
		if (cd "$BASE" && git push origin HEAD:refs/heads/main >"$O" 2>&1); then
			res WS5 FAIL "push from the workspace to main was ACCEPTED: $(brief "$O")"
		elif [ "$(remote_sha refs/heads/main)" != "$MAIN0" ]; then
			res WS5 FAIL "push from the workspace to main reported failure but main moved"
		elif by_proxy "$O"; then
			res WS5 PASS "push from the workspace to main refused: $(brief "$O")"
		else
			res WS5 FAIL "push from the workspace to main failed, but not by the proxy: $(brief "$O")"
		fi
		# Leave the device's workspace as it was provisioned.
		git -C "$BASE" reset -q --hard "$MAIN0" >/dev/null 2>&1
	else
		res WS1 FAIL "the working directory is not a git checkout"
	fi
	expect_allowed W1 "refs/heads/$WS_BRANCH" "push to $WS_BRANCH (inside the grant's branches)" "HEAD:refs/heads/$WS_BRANCH"
	expect_denied W2 "refs/heads/$OTHER" "push to $OTHER (outside the grant's branches)" "HEAD:refs/heads/$OTHER"
	expect_denied W3 refs/heads/main "push to main" HEAD:refs/heads/main
	;;
*)
	res SCENARIO FAIL "unknown scenario $SCENARIO"
	;;
esac

cd "$BASE" && rm -rf "$W"
printf 'SUMMARY %s pass=%d fail=%d\n' "$SCENARIO" "$pass" "$fail"
