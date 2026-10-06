#!/bin/sh
# Kubernetes probe (Task 20385). Runs INSIDE a workload Pod the hub dispatched
# to the in-cluster executor: the stand-in harness (scripts/e2e/gitproxy/claude)
# runs it from the task description, so everything here is what a real
# harness's own git and kubectl would see.
#
# kube_test.go prepends the parameters as shell assignments:
#   REPO, OTHER_REPO  owner/name: the granted repository, and one the same PAT
#                     reaches on the forge but the grant does not name
#   STAMP             unique suffix for every branch this run creates
#   ALLOWED, DENIED   branches inside / outside the grant's branch list (both
#                     inside the hub's refs/heads/cloop/**)
#   BRANCH_RULE       the grant's branch pattern, which a refusal must name
#   K8S_NS            the namespace the kubeconfig grant covers, read-only
#   FORGE_URL         the forge's own in-cluster URL, for the egress check
#   EXPECT_EGRESS_BLOCKED  1 when the hub proved the CNI enforces NetworkPolicy
#
# Every check prints "RESULT <id> PASS|FAIL <detail>"; the run ends with
# SUMMARY. Nothing here prints a credential: a token check reports where a
# token was found, never its value.
#
# Nothing else may reach stdout. `cloop run` shows at most 20 lines of what a
# harness printed — the first ten and the last ten — and captures its stderr
# instead of passing it through, so the stand-in's two lines plus one per check
# and the summary is the whole budget. A diagnostic belongs in a check's detail.
set -u
: "${REPO:?}" "${OTHER_REPO:?}" "${STAMP:?}" "${ALLOWED:?}" "${DENIED:?}" "${BRANCH_RULE:?}" "${K8S_NS:?}"

pass=0
fail=0
res() {
	printf 'RESULT %s %s %s\n' "$1" "$2" "$3"
	if [ "$2" = PASS ]; then pass=$((pass + 1)); else fail=$((fail + 1)); fi
}
# brief renders the lines of a transcript that say what happened, as one line.
brief() {
	grep -E 'remote:|error:|fatal:|rejected|\[new|->|denied|refused|not found|returned error|Forbidden|Error' "$1" |
		tr -s ' \t' ' ' | tail -n 3 | tr '\n' ' ' | cut -c1-300
}
network_failure() { [ ! -s "$1" ] || grep -Eq 'Could not resolve host|Failed to connect|Connection timed out|Connection refused|Network is unreachable|timed out' "$1"; }
by_proxy() { grep -Eq 'cloop git proxy|remote rejected|\(ref update denied|session may not' "$1"; }

GH=https://github.com
BASE=$(pwd)
W=$(mktemp -d "${TMPDIR:-/tmp}/kube-e2e.XXXXXX") || { res SETUP FAIL "no temporary directory"; exit 0; }
O=$W/out.txt
export GIT_TERMINAL_PROMPT=0
GITC="git -c user.name=cloop-e2e -c user.email=cloop-e2e@example.invalid -c commit.gpgsign=false"
TOKRE='(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_.]{20,}|github_pat_[A-Za-z0-9_]{20,}'

# ── The credential helper and the token ───────────────────────────────────
HELPER=${CLOOP_LEASE_DIR:-/nonexistent}/git-credential-cloop
# -L: a projected Secret's file is a symlink into the volume's ..data
# directory, and the link's own mode is always 777.
mode=$(stat -L -c %a "$HELPER" 2>/dev/null || echo missing)
if [ "$mode" = 550 ]; then
	res H1 PASS "the lease's credential helper is mode 0550 ($HELPER, run as $(id -u):$(id -g)), so git can run it as the Pod's group"
else
	res H1 FAIL "the lease's credential helper is mode $mode, not 0550 ($HELPER)"
fi

leak=""
env | grep -Eq "$TOKRE" && leak="$leak env"
[ -n "${CLOOP_LEASE_DIR:-}" ] && grep -rEqs "$TOKRE" "$CLOOP_LEASE_DIR" && leak="$leak lease-dir"
grep -Eqs "$TOKRE" "$BASE/.git/config" && leak="$leak workspace-.git/config"
if [ -z "$leak" ]; then
	res T1 PASS "no GitHub token in the environment, the lease directory or the workspace's git config"
else
	res T1 FAIL "a GitHub token is readable in:$leak"
fi

# ── The CA the chart delivered ────────────────────────────────────────────
if [ -s /etc/cloop/git-ca/ca.crt ] && [ -z "${GIT_SSL_CAINFO:-}" ] &&
	env | grep -q '^GIT_CONFIG_KEY_[0-9]*=http\.https://.*\.sslCAInfo$'; then
	res C1 PASS "the proxy's CA is mounted at /etc/cloop/git-ca/ca.crt and trusted for $(env | sed -n 's/^GIT_CONFIG_KEY_[0-9]*=http\.\(https:.*\)\.sslCAInfo$/\1/p' | head -n 1) only (no GIT_SSL_CAINFO)"
else
	res C1 FAIL "the CA bundle is not delivered as a URL-scoped sslCAInfo (ca=$(ls -l /etc/cloop/git-ca/ca.crt 2>&1 | cut -c1-60), GIT_SSL_CAINFO=${GIT_SSL_CAINFO:-unset})"
fi

# ── The workspace: fetched by the init container through the proxy ─────────
if git -C "$BASE" rev-parse --git-dir >/dev/null 2>&1; then
	WSURL=$(git -C "$BASE" config --get remote.origin.url)
	case $WSURL in
	"${CLOOP_GIT_PROXY_URL:-no-proxy-url}"/*) res WS1 PASS "the workspace was provisioned through the proxy: origin $WSURL" ;;
	*) res WS1 FAIL "the workspace's origin is $WSURL, not the proxy ${CLOOP_GIT_PROXY_URL:-unset}" ;;
	esac
	if grep -qis 'extraheader\|password' "$BASE/.git/config"; then
		res WS2 FAIL "the workspace's .git/config holds a credential"
	else
		res WS2 PASS "no credential in the workspace's .git/config"
	fi
else
	res WS1 FAIL "the working directory is not a git checkout"
fi

# ── Clone and pushes through the proxy ────────────────────────────────────
cd "$W" || exit 0
if git clone -q "$GH/$REPO" repo >"$O" 2>&1; then
	res P1 PASS "cloned $GH/$REPO through $(git -C repo ls-remote --get-url origin)"
else
	res P1 FAIL "clone of the granted $REPO failed: $(brief "$O")"
	printf 'SUMMARY kube pass=%d fail=%d (clone failed)\n' "$pass" "$fail"
	exit 0
fi
cd repo || exit 0
printf 'Task 20385 kube e2e %s\n' "$STAMP" >"t20385-$STAMP.txt"
git add "t20385-$STAMP.txt" && $GITC commit -qm "Task 20385 kube e2e $STAMP" >/dev/null
remote_sha() { git ls-remote origin "$1" 2>/dev/null | cut -f1; }

# kube_test.go reads the commit from this detail: "at <sha>".
if git push origin "HEAD:refs/heads/$ALLOWED" >"$O" 2>&1 && [ "$(remote_sha "refs/heads/$ALLOWED")" = "$(git rev-parse HEAD)" ]; then
	res B1 PASS "push to $ALLOWED (inside the grant's $BRANCH_RULE) accepted at $(git rev-parse HEAD)"
else
	res B1 FAIL "push to $ALLOWED: $(brief "$O")"
fi

before=$(remote_sha "refs/heads/$DENIED")
if git push origin "HEAD:refs/heads/$DENIED" >"$O" 2>&1; then
	res B2 FAIL "push to $DENIED was ACCEPTED: $(brief "$O")"
elif [ "$(remote_sha "refs/heads/$DENIED")" != "$before" ]; then
	res B2 FAIL "push to $DENIED reported failure but the ref moved"
elif ! by_proxy "$O"; then
	res B2 FAIL "push to $DENIED failed, but not with a proxy refusal: $(brief "$O")"
elif ! grep -qF "${BRANCH_RULE#refs/heads/}" "$O"; then
	res B2 FAIL "push to $DENIED refused without naming the grant's branches ($BRANCH_RULE): $(brief "$O")"
else
	res B2 PASS "push to $DENIED refused with the policy message: $(brief "$O")"
fi

if git push "$GH/$OTHER_REPO" "HEAD:refs/heads/$ALLOWED" >"$O" 2>&1; then
	res R1 FAIL "pushed into $OTHER_REPO, which the grant does not name"
elif by_proxy "$O"; then
	res R1 PASS "push into $OTHER_REPO refused by the proxy: $(brief "$O")"
else
	res R1 FAIL "push into $OTHER_REPO refused, but not by the proxy: $(brief "$O")"
fi

# ── The cluster, through the kube guard ───────────────────────────────────
cd "$W" || exit 0
SERVER=$(sed -n 's/^ *server: *//p' "${KUBECONFIG:-/nonexistent}" | head -n 1)
case $SERVER in
*kubernetes.default* | "") res K0 FAIL "the delivered kubeconfig's server is '${SERVER:-none}', not the monitor" ;;
https://*:*) res K0 PASS "the delivered kubeconfig names the monitor ($SERVER), not the API server" ;;
*) res K0 FAIL "the delivered kubeconfig's server is '$SERVER'" ;;
esac
if kubectl get pods -n "$K8S_NS" >"$O" 2>&1; then
	res K1 PASS "kubectl get pods -n $K8S_NS succeeded through the monitor"
else
	res K1 FAIL "kubectl get pods -n $K8S_NS: $(brief "$O")"
fi
# The cluster credential stays in the hub: a ServiceAccount token is a JWT,
# and nothing the Pod can read holds one — the kubeconfig carries a session.
JWTRE='eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}'
jwt=""
env | grep -Eq "$JWTRE" && jwt="$jwt env"
[ -n "${CLOOP_LEASE_DIR:-}" ] && grep -rEqs "$JWTRE" "$CLOOP_LEASE_DIR" && jwt="$jwt lease-dir"
grep -Eqs "$JWTRE" "${KUBECONFIG:-/nonexistent}" && jwt="$jwt kubeconfig"
if [ -z "$jwt" ]; then
	res K3 PASS "no cluster token (JWT) in the environment, the lease directory or the delivered kubeconfig"
else
	res K3 FAIL "a cluster token (JWT) is readable in:$jwt"
fi
if kubectl create configmap "e2e-$STAMP" -n "$K8S_NS" --from-literal=probe=1 >"$O" 2>&1; then
	res K2 FAIL "kubectl create configmap was ALLOWED on a read-only grant"
elif grep -q 'read-only access to the cluster' "$O"; then
	res K2 PASS "kubectl create configmap refused by the monitor: $(brief "$O")"
else
	res K2 FAIL "kubectl create configmap failed, but not with the monitor's refusal: $(brief "$O")"
fi

# ── Egress: what a NetworkPolicy the CNI enforces takes away ──────────────
if [ -n "${FORGE_URL:-}" ]; then
	if [ "${EXPECT_EGRESS_BLOCKED:-0}" = 1 ]; then
		if timeout 15 env GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_COUNT=0 git -c http.sslVerify=false \
			ls-remote "$FORGE_URL/$REPO.git" >"$O" 2>&1; then
			res E1 FAIL "the forge answered this Pod directly, past its NetworkPolicy"
		elif network_failure "$O"; then
			res E1 PASS "the forge is unreachable from this Pod except through the hub: $(brief "$O")"
		else
			res E1 FAIL "the forge was reached directly (it refused only for want of a credential): $(brief "$O")"
		fi
	else
		egress=" (egress blocking not asserted: the hub did not prove this CNI enforces NetworkPolicy)"
	fi
fi

cd / && rm -rf "$W"
printf 'SUMMARY kube pass=%d fail=%d%s\n' "$pass" "$fail" "${egress:-}"
